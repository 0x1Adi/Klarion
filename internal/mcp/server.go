// Package mcp implements a Model Context Protocol server over stdio, exposing
// Klarion's detection + verification pipeline as tools an AI agent can call
// before it writes or commits code. Transport is newline-delimited JSON-RPC
// 2.0, per the MCP stdio transport.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
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
	protocolVersion = "2025-06-18"
	serverName      = "klarion"
	maxLineBytes    = 16 << 20
)

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
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)

	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Bytes()
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
	if err := sc.Err(); err != nil {
		return fmt.Errorf("mcp: read: %w", err)
	}
	return nil
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
	version := protocolVersion
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(params, &p); err == nil && p.ProtocolVersion != "" {
		version = p.ProtocolVersion
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
	if err := verify.Apply(ctx, s.verifier, &s.cfg.AI, candidates); err != nil {
		fmt.Fprintf(os.Stderr, "klarion mcp: verify: %v\n", err)
	}
	// Always redact before returning over the wire.
	for i := range candidates {
		candidates[i].Context = finding.RedactInText(candidates[i].Context, candidates[i].Secret)
		candidates[i].Secret = ""
		candidates[i].LineText = ""
	}
	return candidates
}

func absClean(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
