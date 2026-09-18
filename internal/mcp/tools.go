package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/0x1Adi/Klarion/internal/finding"
	"github.com/0x1Adi/Klarion/internal/verify"
)

// toolDefs returns the MCP tool catalog advertised by tools/list.
func toolDefs() []map[string]any {
	strObj := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required}
	}
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

	return []map[string]any{
		{
			"name": "scan_text",
			"description": "Scan a block of text or source code for leaked secrets (API keys, tokens, " +
				"private keys, credentials). Call this BEFORE writing generated code to a file. Returns any " +
				"findings with an AI verdict (real secret vs false positive). No findings means the text is clean.",
			"inputSchema": strObj(map[string]any{
				"content":  str("the text or source code to scan"),
				"filename": str("optional filename for context (improves rule matching)"),
			}, "content"),
		},
		{
			"name": "scan_file",
			"description": "Scan a file on disk for leaked secrets. Call this before committing a file. " +
				"Returns findings with AI verdicts.",
			"inputSchema": strObj(map[string]any{
				"path": str("path to the file to scan"),
			}, "path"),
		},
		{
			"name": "verify_finding",
			"description": "Adjudicate a single candidate secret: is it a real leaked secret or a false " +
				"positive (placeholder, example, test fixture, non-secret identifier)? Provide the candidate " +
				"value and, ideally, surrounding context.",
			"inputSchema": strObj(map[string]any{
				"secret":  str("the candidate secret value"),
				"context": str("surrounding lines of code for context"),
				"rule_id": str("optional detection rule id"),
			}, "secret"),
		},
	}
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) handleToolCall(ctx context.Context, req *rpcRequest) {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.respondError(req.ID, -32602, "invalid params")
		return
	}
	switch p.Name {
	case "scan_text":
		s.toolScanText(ctx, req.ID, p.Arguments)
	case "scan_file":
		s.toolScanFile(ctx, req.ID, p.Arguments)
	case "verify_finding":
		s.toolVerifyFinding(ctx, req.ID, p.Arguments)
	default:
		s.respond(req.ID, toolError("unknown tool: "+p.Name))
	}
}

func (s *Server) toolScanText(ctx context.Context, id json.RawMessage, args json.RawMessage) {
	var a struct {
		Content  string `json:"content"`
		Filename string `json:"filename"`
	}
	if err := json.Unmarshal(args, &a); err != nil || a.Content == "" {
		s.respond(id, toolError("scan_text requires a non-empty 'content'"))
		return
	}
	path := a.Filename
	if path == "" {
		path = "<scan_text>"
	}
	findings := s.scanToVerdicts(ctx, path, []byte(a.Content))
	s.respond(id, s.findingsResult(findings))
}

func (s *Server) toolScanFile(ctx context.Context, id json.RawMessage, args json.RawMessage) {
	var a struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &a); err != nil || a.Path == "" {
		s.respond(id, toolError("scan_file requires a 'path'"))
		return
	}
	content, err := os.ReadFile(absClean(a.Path))
	if err != nil {
		s.respond(id, toolError(fmt.Sprintf("cannot read %s: %v", a.Path, err)))
		return
	}
	findings := s.scanToVerdicts(ctx, a.Path, content)
	s.respond(id, s.findingsResult(findings))
}

func (s *Server) toolVerifyFinding(ctx context.Context, id json.RawMessage, args json.RawMessage) {
	var a struct {
		Secret  string `json:"secret"`
		Context string `json:"context"`
		RuleID  string `json:"rule_id"`
	}
	if err := json.Unmarshal(args, &a); err != nil || a.Secret == "" {
		s.respond(id, toolError("verify_finding requires a 'secret'"))
		return
	}
	ruleID := a.RuleID
	if ruleID == "" {
		ruleID = "manual"
	}
	if s.delegating() {
		value := a.Secret
		if !s.cfg.AI.SendSecret {
			value = finding.Redact(value)
		}
		s.respond(id, jsonResult(map[string]any{
			"adjudicated_by":     "calling-agent",
			"needs_adjudication": true,
			"summary": "Klarion has no AI provider configured and did not judge this candidate. " +
				"Apply the rules below; treat uncertain as secret.",
			"candidate": map[string]any{"rule_id": ruleID, "secret": value, "context": a.Context},
			"rules":     verify.Rules(),
		}))
		return
	}
	batch := []verify.Request{{
		Index:   0,
		RuleID:  ruleID,
		Secret:  a.Secret,
		Context: a.Context,
	}}
	verdicts, err := s.verifier.Verify(ctx, batch)
	if err != nil || len(verdicts) == 0 {
		s.respond(id, toolError(fmt.Sprintf("verification failed: %v", err)))
		return
	}
	s.respond(id, jsonResult(map[string]any{
		"verdict":    verdicts[0].Status,
		"confidence": verdicts[0].Confidence,
		"reason":     verdicts[0].Reason,
		"verifier":   verdicts[0].Verifier,
	}))
}

// --- MCP tool result shaping ----------------------------------------------

func (s *Server) findingsResult(findings []finding.Finding) map[string]any {
	if s.delegating() {
		return s.agentResult(findings)
	}
	summary := "No secrets detected — the content appears clean."
	if len(findings) > 0 {
		summary = fmt.Sprintf("%d potential secret(s) detected. Review before writing/committing.", len(findings))
	}
	payload := map[string]any{
		"clean":    len(findings) == 0,
		"count":    len(findings),
		"summary":  summary,
		"findings": findings,
	}
	return jsonResult(payload)
}

// agentResult hands the candidates to the calling agent together with the rules
// Klarion's own verifier follows. The verdict is then the agent's, not
// Klarion's, and the payload says so: no benchmark claim attaches to this path.
func (s *Server) agentResult(fs []finding.Finding) map[string]any {
	if len(fs) == 0 {
		return jsonResult(map[string]any{
			"clean": true, "count": 0,
			"adjudicated_by": "calling-agent", "needs_adjudication": false,
			"summary": "No secret candidates detected — nothing to judge.",
		})
	}
	return jsonResult(map[string]any{
		"clean": false, "count": len(fs),
		"adjudicated_by": "calling-agent", "needs_adjudication": true,
		"summary": fmt.Sprintf("Klarion has no AI provider configured, so it did not judge these %d "+
			"candidate(s). Apply the rules below to each one. Treat uncertain as secret: do not write or "+
			"commit a value you judge to be a secret, tell the user, and move it to a secrets manager.", len(fs)),
		"rules":      verify.Rules(),
		"candidates": verify.Candidates(fs, &s.cfg.AI),
	})
}

func jsonResult(payload any) map[string]any {
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return toolError("internal marshal error")
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(b)}},
		"isError": false,
	}
}

func toolError(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}
