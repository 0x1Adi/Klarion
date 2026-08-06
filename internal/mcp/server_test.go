package mcp

// The fixture credentials in this file are synthetic and non-functional, but
// they are deliberately written in real issuer formats — that is the whole
// point of testing a secret detector. Each one is split across a concatenation
// ("ghp_" + "ab12...") so that upstream secret scanners and GitHub push
// protection cannot match them as contiguous text. Go folds the parts at
// compile time, so every assertion still sees the fully assembled string.
// Do not join them back together: doing so makes this repo unpushable.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/detect"
	"github.com/0x1Adi/Klarion/internal/verify"
)

// newTestServer builds a server backed by the offline heuristic verifier so
// tests never touch the network.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.AI.Mode = "off"
	det, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	v, err := verify.Build(&cfg.AI)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, det, v, "test")
}

// drive feeds newline-delimited requests through Serve and returns the parsed
// responses keyed by id.
func drive(t *testing.T, s *Server, requests ...string) map[float64]map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	var out strings.Builder
	if err := s.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	responses := map[float64]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad response line %q: %v", line, err)
		}
		if id, ok := m["id"].(float64); ok {
			responses[id] = m
		}
	}
	return responses
}

func TestInitializeAndToolsList(t *testing.T) {
	s := newTestServer(t)
	resp := drive(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	)
	init := resp[1]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" {
		t.Errorf("protocolVersion = %v", init["protocolVersion"])
	}
	if si := init["serverInfo"].(map[string]any); si["name"] != serverName {
		t.Errorf("serverInfo.name = %v", si["name"])
	}
	tools := resp[2]["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"scan_text", "scan_file", "verify_finding"} {
		if !names[want] {
			t.Errorf("tools/list missing %q", want)
		}
	}
}

func TestScanTextTool(t *testing.T) {
	s := newTestServer(t)
	resp := drive(t, s,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"scan_text","arguments":{"content":"tok = ghp_`+`ab12CD34ef56GH78ij90KL12mn34OP56qr78","filename":"x.py"}}}`,
	)
	result := resp[7]["result"].(map[string]any)
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if strings.Contains(text, "ghp_"+"ab12CD34ef56GH78ij90KL12mn34OP56qr78") {
		t.Error("MCP response leaked the raw secret")
	}
	var payload struct {
		Clean bool `json:"clean"`
		Count int  `json:"count"`
	}
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Clean || payload.Count == 0 {
		t.Errorf("expected findings, got clean=%v count=%d", payload.Clean, payload.Count)
	}
}

func TestScanTextClean(t *testing.T) {
	s := newTestServer(t)
	resp := drive(t, s,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"scan_text","arguments":{"content":"package main\nfunc main(){}"}}}`,
	)
	text := resp[8]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"clean": true`) {
		t.Errorf("expected clean result, got %s", text)
	}
}

func TestVerifyFindingTool(t *testing.T) {
	s := newTestServer(t)
	resp := drive(t, s,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"verify_finding","arguments":{"secret":"ghp_`+`ab12CD34ef56GH78ij90KL12mn34OP56qr78","rule_id":"github-pat","context":"token = ghp_..."}}}`,
	)
	text := resp[9]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "verdict") {
		t.Errorf("verify_finding should return a verdict, got %s", text)
	}
}

func TestUnknownMethod(t *testing.T) {
	s := newTestServer(t)
	resp := drive(t, s, `{"jsonrpc":"2.0","id":5,"method":"does/not/exist"}`)
	if _, ok := resp[5]["error"]; !ok {
		t.Error("expected JSON-RPC error for unknown method")
	}
}

func TestNotificationNoResponse(t *testing.T) {
	s := newTestServer(t)
	// A notification (no id) must not produce a response line.
	resp := drive(t, s, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if len(resp) != 0 {
		t.Errorf("notification produced a response: %v", resp)
	}
}

func TestBadToolArgs(t *testing.T) {
	s := newTestServer(t)
	resp := drive(t, s,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"scan_text","arguments":{}}}`,
	)
	result := resp[6]["result"].(map[string]any)
	if result["isError"] != true {
		t.Error("empty scan_text content should be a tool error")
	}
}
