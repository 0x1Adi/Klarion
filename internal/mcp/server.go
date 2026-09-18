// Package mcp implements a Model Context Protocol server over stdio, exposing
// Klarion's detection + verification pipeline as tools an AI agent can call
// before it writes or commits code. Transport is newline-delimited JSON-RPC
// 2.0, per the MCP stdio transport.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/detect"
	"github.com/0x1Adi/Klarion/internal/finding"
	"github.com/0x1Adi/Klarion/internal/verify"
)

const (
	protocolVersion = "2025-06-18" // newest revision this server implements
	serverName      = "klarion"
	maxLineBytes    = 16 << 20
)

// supportedVersions are the revisions this server speaks, newest first. A
// tools-only stdio server is wire-compatible across these three.
var supportedVersions = []string{protocolVersion, "2025-03-26", "2024-11-05"}

// Server holds the pipeline shared by every tool call.
type Server struct {
	cfg      *config.Config
	detector *detect.Detector
	verifier verify.Verifier
	version  string

	mu  sync.Mutex // serializes writes to the output stream
	out *bufio.Writer
}

// New constructs an MCP server around a configured pipeline.
func New(cfg *config.Config, det *detect.Detector, v verify.Verifier, version string) *Server {
	return &Server{cfg: cfg, detector: det, verifier: v, version: version}
}

// --- JSON-RPC envelope -----------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Serve runs the read→dispatch→write loop until in is exhausted or ctx is done.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.out = bufio.NewWriter(out)
	r := bufio.NewReaderSize(in, 64<<10)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line, oversized, err := readFrame(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("mcp: read: %w", err)
		}
		if oversized {
			// One outsized message must not end the session. An agent that
			// pasted a huge file still needs the rest of its tool calls, and a
			// server that exits here looks to the client like a crash.
			s.respondError(nil, -32600, fmt.Sprintf("message exceeds the %d byte limit", maxLineBytes))
			continue
		}
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.respondError(nil, -32700, "parse error")
			continue
		}
		s.dispatch(ctx, &req)
	}
}

// readFrame reads one newline-delimited frame. A frame longer than
// maxLineBytes is discarded up to the next newline and reported as oversized,
// so the reader never holds more than the limit and the loop can continue.
func readFrame(r *bufio.Reader) ([]byte, bool, error) {
	var buf []byte
	oversized := false
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, false, err
		}
		if !oversized {
			if len(buf)+len(chunk) > maxLineBytes {
				oversized, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if !isPrefix {
			return buf, oversized, nil
		}
	}
}

func (s *Server) dispatch(ctx context.Context, req *rpcRequest) {
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	switch req.Method {
	case "initialize":
		s.respond(req.ID, s.initializeResult(req.Params))
	case "notifications/initialized", "notifications/cancelled":
		// Notifications: no response.
	case "ping":
		s.respond(req.ID, map[string]any{})
	case "tools/list":
		s.respond(req.ID, map[string]any{"tools": toolDefs()})
	case "tools/call":
		s.handleToolCall(ctx, req)
	default:
		if !isNotification {
			s.respondError(req.ID, -32601, "method not found: "+req.Method)
		}
	}
}

func (s *Server) initializeResult(params json.RawMessage) map[string]any {
	// Spec: answer with the client's version when we support it, otherwise with
	// one we do, so the client can decide whether to keep talking. Echoing an
	// unknown version claims support we have not got.
	version := protocolVersion
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(params, &p); err == nil {
		for _, v := range supportedVersions {
			if p.ProtocolVersion == v {
				version = v
				break
			}
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": serverName, "version": s.version},
		"instructions": "Call scan_text before writing generated code, or scan_file " +
			"before committing, to detect leaked secrets. verify_finding adjudicates a " +
			"single candidate. Klarion errs toward flagging when uncertain.",
	}
}

// --- write helpers ---------------------------------------------------------

func (s *Server) respond(id json.RawMessage, result any) {
	s.write(rpcResponse{JSONRPC: "2.0", ID: idOrNull(id), Result: result})
}

func (s *Server) respondError(id json.RawMessage, code int, msg string) {
	s.write(rpcResponse{JSONRPC: "2.0", ID: idOrNull(id), Error: &rpcError{Code: code, Message: msg}})
}

func (s *Server) write(resp rpcResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "klarion mcp: marshal: %v\n", err)
		return
	}
	s.out.Write(b)
	s.out.WriteByte('\n')
	s.out.Flush()
}

func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

// scanToVerdicts runs the full pipeline over one blob and returns the
// (sanitized) findings, verdicts applied.
func (s *Server) scanToVerdicts(ctx context.Context, path string, content []byte) []finding.Finding {
	candidates := s.detector.ScanContent(path, content)
	if len(candidates) == 0 {
		return nil
	}
	// The agent-facing surface must report what `klarion scan` reports. One
	// wrapped key is one finding, not one per base64 line (which also costs one
	// model call per line), and a candidate the verifier rejected is not a
	// finding: an agent that gets rejected candidates back learns to ignore us.
	candidates = finding.CollapseKeyBlocks(candidates)
	if err := verify.Apply(ctx, s.verifier, &s.cfg.AI, candidates); err != nil {
		fmt.Fprintf(os.Stderr, "klarion mcp: verify: %v\n", err)
	}
	kept, _ := verify.FilterFalsePositives(candidates, &s.cfg.AI)
	// Always redact before returning over the wire.
	for i := range kept {
		kept[i].Context = finding.RedactInText(kept[i].Context, kept[i].Secret)
		kept[i].Secret = ""
		kept[i].LineText = ""
	}
	return kept
}

func absClean(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
