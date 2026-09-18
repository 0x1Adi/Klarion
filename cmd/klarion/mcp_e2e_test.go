package main

// End-to-end tests for `klarion mcp`, driven the way a real MCP client (Claude
// Code, Cline) drives it: a separate process, real stdio pipes, real
// newline-delimited JSON-RPC bytes, one long-lived session per test.
//
// Hermetic by default — ai.mode = "off", a scrubbed environment with no
// provider keys, no network — so CI spends no model tokens. Set
// KLARION_E2E_AI=1 to additionally run the configured provider end to end.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// buildKlarion compiles the real binary once per test binary run. Tests that do
// not need it pay nothing.
var buildKlarion = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "klarion-mcp-e2e")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "klarion")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go build: %v\n%s", err, out)
	}
	return bin, nil
})

type session struct {
	t       *testing.T
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	lines   chan string
	stderr  *bytes.Buffer
	stdout  []string // every line the server wrote, for the protocol-purity test
	nextID  int
	exited  chan struct{}
	waitErr error
}

// start launches `klarion mcp` with an explicit config and a scrubbed
// environment. extraEnv entries are appended (nil for the hermetic default).
func start(t *testing.T, configTOML string, extraEnv ...string) *session {
	t.Helper()
	bin, err := buildKlarion()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "klarion.toml")
	if err := os.WriteFile(cfg, []byte(configTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "mcp", "--config", cfg)
	cmd.Dir = dir
	// A client inherits the operator's environment; we scrub it so a stray key
	// on the developer's machine cannot turn a hermetic test into a paid one.
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}, extraEnv...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	s := &session{t: t, cmd: cmd, stdin: stdin, lines: make(chan string, 64),
		stderr: &bytes.Buffer{}, nextID: 1, exited: make(chan struct{})}
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
		for sc.Scan() {
			s.lines <- sc.Text()
		}
		close(s.lines)
	}()
	go func() { s.waitErr = cmd.Wait(); close(s.exited) }()
	t.Cleanup(func() {
		_ = stdin.Close()
		select {
		case <-s.exited:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	})
	return s
}

func (s *session) send(method string, params any) int {
	s.t.Helper()
	id := s.nextID
	s.nextID++
	msg := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	s.writeRaw(mustJSON(s.t, msg))
	return id
}

func (s *session) notify(method string, params any) {
	s.t.Helper()
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		msg["params"] = params
	}
	s.writeRaw(mustJSON(s.t, msg))
}

// writeRaw writes one frame. A dead server is reported, not fatal: several
// tests assert what happens after the server gives up.
func (s *session) writeRaw(line string) {
	if _, err := io.WriteString(s.stdin, line+"\n"); err != nil {
		s.t.Logf("write %q: %v", truncate(line, 60), err)
	}
}

// next returns the next frame the server wrote, or fails if it writes nothing.
func (s *session) next(timeout time.Duration) map[string]any {
	s.t.Helper()
	select {
	case line, ok := <-s.lines:
		if !ok {
			s.t.Fatalf("server closed stdout; stderr: %s", s.stderr.String())
		}
		s.stdout = append(s.stdout, line)
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			s.t.Fatalf("stdout line is not JSON: %q", truncate(line, 200))
		}
		return m
	case <-time.After(timeout):
		s.t.Fatalf("no response within %s; stderr: %s", timeout, s.stderr.String())
		return nil
	}
}

// call sends a request and returns the response with the matching id, skipping
// any server-initiated frames in between.
func (s *session) call(method string, params any) map[string]any {
	s.t.Helper()
	id := s.send(method, params)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		m := s.next(time.Until(deadline))
		if got, ok := m["id"].(float64); ok && int(got) == id {
			return m
		}
	}
	s.t.Fatalf("no response to %s (id %d)", method, id)
	return nil
}

// handshake runs the initialize / initialized exchange every client performs.
func (s *session) handshake() map[string]any {
	s.t.Helper()
	res := result(s.t, s.call("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "e2e", "version": "1.0.0"},
	}))
	s.notify("notifications/initialized", nil)
	return res
}

// scanResult is the payload Klarion packs into the tool result's text content.
type scanResult struct {
	Clean    bool   `json:"clean"`
	Count    int    `json:"count"`
	Summary  string `json:"summary"`
	Findings []struct {
		RuleID   string `json:"rule_id"`
		File     string `json:"file"`
		Line     int    `json:"line"`
		Severity string `json:"severity"`
		Redacted string `json:"secret_redacted"`
		Verdict  struct {
			Status   string `json:"status"`
			Verifier string `json:"verifier"`
		} `json:"verdict"`
	} `json:"findings"`
}

// callTool calls a tool and returns the decoded payload, the isError flag, and
// the raw response line (for leak checks).
func (s *session) callTool(name string, args map[string]any) (scanResult, bool, string) {
	s.t.Helper()
	resp := s.call("tools/call", map[string]any{"name": name, "arguments": args})
	raw := mustJSON(s.t, resp)
	res := result(s.t, resp)
	isErr, _ := res["isError"].(bool)
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		s.t.Fatalf("%s: no content in %s", name, truncate(raw, 300))
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	var out scanResult
	if err := json.Unmarshal([]byte(text), &out); err != nil && !isErr {
		s.t.Fatalf("%s: result text is not the JSON payload: %q", name, truncate(text, 200))
	}
	return out, isErr, raw
}

func (s *session) waitExit(timeout time.Duration) (int, bool) {
	s.t.Helper()
	select {
	case <-s.exited:
		return s.cmd.ProcessState.ExitCode(), true
	case <-time.After(timeout):
		return 0, false
	}
}

func result(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	if e, ok := resp["error"]; ok {
		t.Fatalf("unexpected JSON-RPC error: %v", e)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Fatalf("missing jsonrpc 2.0 in %v", resp)
	}
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result object in %v", resp)
	}
	return res
}

func rpcError(t *testing.T, resp map[string]any) (int, string) {
	t.Helper()
	e, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected a JSON-RPC error, got %v", resp)
	}
	code, _ := e["code"].(float64)
	msg, _ := e["message"].(string)
	return int(code), msg
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Fake credentials, never issued. They are assembled from parts on purpose: a
// test file that spells a live-format key out in one piece trips every scanner
// it passes through, including GitHub push protection and Klarion itself. The
// values are whole again at run time, which is all the detector sees.
const (
	stripeKey      = "sk_" + "live_51H8xQ2eZvKYlo2C9mVbN3pRtYuIoPaSdFgHj"
	awsKey         = "AKIA" + "2E4XMPL7QZKJ3RTB"
	placeholderKey = "sk_" + "live_EXAMPLE9xNotARealKeyForDocsOnly12"
)

// --- session lifecycle ----------------------------------------------------

func TestMCPHandshakeAndCatalog(t *testing.T) {
	s := start(t, noAI)
	res := s.handshake()

	if res["protocolVersion"] != "2025-06-18" {
		t.Errorf("protocolVersion = %v, want 2025-06-18", res["protocolVersion"])
	}
	info, _ := res["serverInfo"].(map[string]any)
	if info["name"] != "klarion" || info["version"] == "" {
		t.Errorf("serverInfo = %v, want name klarion and a version", info)
	}
	caps, _ := res["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Errorf("capabilities = %v, want a tools capability", caps)
	}
	if instr, _ := res["instructions"].(string); instr == "" {
		t.Error("no instructions: clients show these to the model")
	}

	// tools/list is what the agent actually sees.
	list := result(t, s.call("tools/list", nil))
	tools, _ := list["tools"].([]any)
	got := map[string]bool{}
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		name, _ := tool["name"].(string)
		got[name] = true
		if desc, _ := tool["description"].(string); len(desc) < 20 {
			t.Errorf("%s: description too thin for a model to route on: %q", name, desc)
		}
		schema, ok := tool["inputSchema"].(map[string]any)
		if !ok || schema["type"] != "object" {
			t.Fatalf("%s: inputSchema is not an object schema: %v", name, tool["inputSchema"])
		}
		req, _ := schema["required"].([]any)
		if len(req) == 0 {
			t.Errorf("%s: schema declares no required argument", name)
		}
		props, _ := schema["properties"].(map[string]any)
		for pname, p := range props {
			pm, _ := p.(map[string]any)
			if pm["type"] == nil || pm["description"] == nil {
				t.Errorf("%s.%s: property needs a type and a description, got %v", name, pname, pm)
			}
		}
	}
	for _, want := range []string{"scan_text", "scan_file", "verify_finding"} {
		if !got[want] {
			t.Errorf("tools/list is missing %s", want)
		}
	}

	// ping keeps clients from treating the session as hung.
	if _, ok := result(t, s.call("ping", nil))["_"]; ok {
		t.Error("ping result should be an empty object")
	}
}

// The spec: a server that does not support the requested version MUST answer
// with a version it does support, never echo the client's.
func TestMCPVersionNegotiation(t *testing.T) {
	s := start(t, noAI)
	res := result(t, s.call("initialize", map[string]any{
		"protocolVersion": "1999-01-01",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "e2e", "version": "1.0.0"},
	}))
	if got := res["protocolVersion"]; got == "1999-01-01" {
		t.Errorf("echoed the client's unsupported protocolVersion %v; MUST answer with a supported one", got)
	} else if got != "2025-06-18" {
		t.Errorf("protocolVersion = %v, want the newest supported revision", got)
	}

	// An older client that we do speak must get its own version back, or it
	// disconnects.
	old := result(t, s.call("initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "e2e", "version": "1.0.0"},
	}))
	if got := old["protocolVersion"]; got != "2024-11-05" {
		t.Errorf("protocolVersion = %v for a supported client revision, want 2024-11-05", got)
	}
}

func TestMCPCleanShutdownOnEOF(t *testing.T) {
	s := start(t, noAI)
	s.handshake()
	if err := s.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	code, exited := s.waitExit(5 * time.Second)
	if !exited {
		t.Fatal("server did not exit within 5s of stdin closing; clients would have to SIGKILL it")
	}
	if code != 0 {
		t.Errorf("exit code %d on clean disconnect, want 0; stderr: %s", code, s.stderr.String())
	}
}

// Installed from a registry with no Klarion config, the server has no provider.
// Whatever it does then must be loud and fast, and must not look like a server
// that came up healthy.
func TestMCPNoProviderStartup(t *testing.T) {
	s := start(t, "[ai]\nmode = \"on\"\n")
	code, exited := s.waitExit(10 * time.Second)
	if !exited {
		t.Fatal("server neither served nor exited with no provider configured")
	}
	if code == 0 {
		t.Errorf("exit code 0 with no provider; want a non-zero code so the client reports a failed start")
	}
	if err := s.stderr.String(); !strings.Contains(err, "provider") && !strings.Contains(err, "API_KEY") {
		t.Errorf("stderr does not say what is missing: %q", err)
	}
	if len(s.stdout) > 0 {
		t.Errorf("wrote %d frames to stdout before failing: %v", len(s.stdout), s.stdout)
	}
}

// --- detection behavior ---------------------------------------------------

func TestMCPScanTextFindsProviderKey(t *testing.T) {
	s := start(t, noAI)
	s.handshake()
	res, isErr, raw := s.callTool("scan_text", map[string]any{
		"content":  fmt.Sprintf("import stripe\nstripe.api_key = %q\n", stripeKey),
		"filename": "billing/client.py",
	})
	if isErr {
		t.Fatalf("tool reported an error: %s", truncate(raw, 300))
	}
	if res.Count == 0 || res.Clean {
		t.Fatalf("missed a live-format Stripe key: %+v", res)
	}
	f := res.Findings[0]
	if f.RuleID != "stripe-secret-key" {
		t.Errorf("rule_id = %q, want stripe-secret-key", f.RuleID)
	}
	if f.Severity != "critical" {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if f.File != "billing/client.py" || f.Line != 2 {
		t.Errorf("located at %s:%d, want billing/client.py:2", f.File, f.Line)
	}
	if f.Redacted == "" || !strings.Contains(f.Redacted, "*") {
		t.Errorf("secret_redacted = %q, want a masked value", f.Redacted)
	}
	// The whole frame crosses to the agent and into its transcript.
	if strings.Contains(raw, stripeKey) {
		t.Error("the raw secret appears in the tool result")
	}
}

// cleanGoCode is the documented false-positive class: long CamelCase and
// SCREAMING_SNAKE identifiers, which carry the same character distribution as
// key material.
const cleanGoCode = `package s3
const (
	SseCustomerKeySHA256AttrName = "x-amz-server-side-encryption-customer-key-SHA256"
	PROVIDER_SECURITY_TOKEN      = "TENCENTCLOUD_SECURITY_TOKEN"
)
func applyDecs2301Factory(t *Transport) *Transport { return t }
`

// A candidate the verifier rejected is not a finding. `klarion scan` drops
// these; the agent-facing tool must drop them too, or the agent learns to
// ignore us.
func TestMCPRejectedCandidatesAreNotFindings(t *testing.T) {
	s := start(t, noAI)
	s.handshake()
	res, _, raw := s.callTool("scan_text", map[string]any{
		// Placeholder markers make this a false positive with no model needed.
		"content":  "api_key = \"" + placeholderKey + "\"\n",
		"filename": "docs/quickstart.py",
	})
	if res.Count != 0 || !res.Clean {
		t.Errorf("reported %d candidate(s) the verifier rejected: %s", res.Count, truncate(raw, 500))
	}
}

// Without a model, entropy alone cannot clear these, and Klarion says so rather
// than calling them secrets. The model path (KLARION_E2E_AI=1) asserts the
// stronger claim that they come back clean.
func TestMCPCleanCodeIsUncertainWithoutAModel(t *testing.T) {
	s := start(t, noAI)
	s.handshake()
	res, _, raw := s.callTool("scan_text", map[string]any{"content": cleanGoCode, "filename": "s3/attrs.go"})
	for _, f := range res.Findings {
		if f.Verdict.Status != "uncertain" {
			t.Errorf("identifier %s reported as %q with no model configured, want uncertain: %s",
				f.Redacted, f.Verdict.Status, truncate(raw, 400))
		}
		if f.Verdict.Verifier != "heuristic" {
			t.Errorf("verifier = %q, want heuristic", f.Verdict.Verifier)
		}
	}
}

// A wrapped private key is one credential. Reporting one finding per base64
// line floods the agent and multiplies model calls.
func TestMCPPrivateKeyIsOneFinding(t *testing.T) {
	s := start(t, noAI)
	s.handshake()
	// A real key body is random, so build one: repeated identical lines carry
	// no entropy and would not be a fair fixture.
	seed := make([]byte, 1200)
	rnd := rand.New(rand.NewSource(1))
	rnd.Read(seed)
	b64 := base64.StdEncoding.EncodeToString(seed)
	var body strings.Builder
	for i := 0; i < len(b64); i += 64 {
		body.WriteString(b64[i:min(i+64, len(b64))] + "\n")
	}
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + body.String() + "-----END RSA PRIVATE KEY-----\n"
	res, _, raw := s.callTool("scan_text", map[string]any{"content": pem, "filename": "deploy/id_rsa"})
	if res.Count != 1 {
		t.Errorf("one private key reported as %d finding(s): %s", res.Count, truncate(raw, 400))
	}
}

func TestMCPScanFile(t *testing.T) {
	s := start(t, noAI)
	s.handshake()
	dir := t.TempDir()
	good := filepath.Join(dir, "config.py")
	if err := os.WriteFile(good, []byte("AWS_ACCESS_KEY_ID = \""+awsKey+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		args    map[string]any
		wantErr bool
		wantHit bool
	}{
		{"real file", map[string]any{"path": good}, false, true},
		{"missing file", map[string]any{"path": filepath.Join(dir, "nope.py")}, true, false},
		{"directory", map[string]any{"path": dir}, true, false},
		{"no path argument", map[string]any{}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, isErr, raw := s.callTool("scan_file", tc.args)
			if isErr != tc.wantErr {
				t.Fatalf("isError = %v, want %v: %s", isErr, tc.wantErr, truncate(raw, 300))
			}
			if !tc.wantErr && (res.Count == 0) == tc.wantHit {
				t.Errorf("count = %d, wantHit = %v", res.Count, tc.wantHit)
			}
			if tc.wantHit && strings.Contains(raw, awsKey) {
				t.Error("the raw secret appears in the tool result")
			}
		})
	}
}

func TestMCPVerifyFinding(t *testing.T) {
	s := start(t, noAI)
	s.handshake()
	for _, tc := range []struct {
		name, secret, context string
		wantErr               bool
	}{
		{"placeholder", "your_api_key_here", "api_key = \"your_api_key_here\"", false},
		{"real looking", stripeKey, "stripe.api_key = \"" + stripeKey + "\"", false},
		{"no secret argument", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{}
			if tc.secret != "" {
				args["secret"] = tc.secret
				args["context"] = tc.context
			}
			resp := s.call("tools/call", map[string]any{"name": "verify_finding", "arguments": args})
			res := result(t, resp)
			isErr, _ := res["isError"].(bool)
			if isErr != tc.wantErr {
				t.Fatalf("isError = %v, want %v: %s", isErr, tc.wantErr, truncate(mustJSON(t, resp), 300))
			}
			if tc.wantErr {
				return
			}
			var v struct {
				Verdict  string `json:"verdict"`
				Verifier string `json:"verifier"`
			}
			text := res["content"].([]any)[0].(map[string]any)["text"].(string)
			if err := json.Unmarshal([]byte(text), &v); err != nil {
				t.Fatalf("verdict payload: %v (%q)", err, truncate(text, 200))
			}
			switch v.Verdict {
			case "secret", "false_positive", "uncertain":
			default:
				t.Errorf("verdict = %q, want secret|false_positive|uncertain", v.Verdict)
			}
			if v.Verifier == "" {
				t.Error("no verifier named: the agent cannot tell a model verdict from a heuristic one")
			}
		})
	}
}

// --- protocol robustness --------------------------------------------------

func TestMCPBadInputKeepsSessionAlive(t *testing.T) {
	s := start(t, noAI)
	s.handshake()

	s.writeRaw("{not json")
	if code, _ := rpcError(t, s.next(10*time.Second)); code != -32700 {
		t.Errorf("parse error code = %d, want -32700", code)
	}

	if code, _ := rpcError(t, s.call("no/such/method", nil)); code != -32601 {
		t.Errorf("unknown method code = %d, want -32601", code)
	}

	// Real clients probe these even when the capability is not advertised.
	for _, m := range []string{"resources/list", "prompts/list"} {
		if code, _ := rpcError(t, s.call(m, nil)); code != -32601 {
			t.Errorf("%s code = %d, want -32601", m, code)
		}
	}

	_, isErr, raw := s.callTool("tools/call_that_does_not_exist", nil)
	if !isErr {
		t.Errorf("unknown tool did not set isError: %s", truncate(raw, 200))
	}
	if _, isErr, _ := s.callTool("scan_text", map[string]any{}); !isErr {
		t.Error("scan_text without content did not set isError")
	}

	// Still usable after all of that.
	result(t, s.call("ping", nil))
}

// Anything on stdout that is not a JSON-RPC frame breaks every client. This is
// the classic way an MCP server dies in the field: one stray log line.
func TestMCPStdoutCarriesOnlyProtocolFrames(t *testing.T) {
	s := start(t, noAI)
	s.handshake()
	s.call("tools/list", nil)
	s.callTool("scan_text", map[string]any{"content": "token = \"" + stripeKey + "\"", "filename": "a.py"})
	s.callTool("scan_file", map[string]any{"path": filepath.Join(t.TempDir(), "absent")})
	s.writeRaw("{not json")
	s.next(10 * time.Second)
	s.call("ping", nil)

	if len(s.stdout) < 5 {
		t.Fatalf("captured only %d frames", len(s.stdout))
	}
	for i, line := range s.stdout {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("stdout line %d is not JSON: %q", i, truncate(line, 120))
			continue
		}
		if m["jsonrpc"] != "2.0" {
			t.Errorf("stdout line %d is not a JSON-RPC 2.0 frame: %q", i, truncate(line, 120))
		}
	}
}

// Agents paste whole files into scan_text.
func TestMCPLargePayload(t *testing.T) {
	s := start(t, noAI)
	s.handshake()
	content := strings.Repeat("func handler(w http.ResponseWriter, r *http.Request) { _ = r.Context() }\n", 30_000)
	content += "stripe.api_key = \"" + stripeKey + "\"\n"
	if len(content) < 2<<20 {
		t.Fatalf("payload only %d bytes", len(content))
	}
	t0 := time.Now()
	res, isErr, raw := s.callTool("scan_text", map[string]any{"content": content, "filename": "big.go"})
	if isErr {
		t.Fatalf("2 MB payload errored: %s", truncate(raw, 300))
	}
	if res.Count == 0 {
		t.Error("the key on the last line of a 2 MB payload was not reported")
	}
	if d := time.Since(t0); d > 30*time.Second {
		t.Errorf("2 MB scan took %s", d)
	}
}

// Over the 16 MB frame limit the server must say something and keep serving, or
// at minimum die visibly. What it must not do is hang or answer as if it had
// scanned the content.
func TestMCPOversizedFrame(t *testing.T) {
	s := start(t, noAI)
	s.handshake()
	huge := strings.Repeat("A", 17<<20)
	id := s.send("tools/call", map[string]any{
		"name": "scan_text", "arguments": map[string]any{"content": huge, "filename": "huge.txt"},
	})
	select {
	case line, ok := <-s.lines:
		if !ok {
			if code, exited := s.waitExit(5 * time.Second); exited && code != 0 {
				t.Logf("server exited with code %d on an oversized frame (stderr: %s)",
					code, truncate(s.stderr.String(), 200))
			}
			t.Error("server dropped the session on an oversized frame instead of answering with an error")
			return
		}
		s.stdout = append(s.stdout, line)
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not a frame: %q", truncate(line, 200))
		}
		if _, ok := m["error"]; !ok {
			t.Errorf("answered an oversized frame with a result rather than an error: %s", truncate(line, 200))
		}
		if got, _ := m["id"].(float64); int(got) != id && m["id"] != nil {
			t.Errorf("error id = %v, want %d or null", m["id"], id)
		}
		result(t, s.call("ping", nil)) // still alive
	case <-time.After(30 * time.Second):
		t.Error("no answer and no exit on an oversized frame: the client would hang until its own timeout")
	}
}

// The standing rule: never reach for a model the operator did not configure.
// `claude` on PATH must stay untouched unless ai.provider says claude-cli.
func TestMCPNeverRunsClaudeImplicitly(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "claude-was-run")
	stub := filepath.Join(dir, "claude")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 1\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	s := start(t, "[ai]\nmode = \"auto\"\n", "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	s.handshake()
	res, _, _ := s.callTool("scan_text", map[string]any{
		"content": "stripe.api_key = \"" + stripeKey + "\"\n", "filename": "pay.py",
	})
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("ran the claude CLI without ai.provider = claude-cli")
	}
	if res.Count > 0 && res.Findings[0].Verdict.Verifier == "claude-cli" {
		t.Errorf("verdict came from claude-cli: %+v", res.Findings[0].Verdict)
	}
}

// The paid path, run only on demand:
//
//	KLARION_E2E_AI=1 KLARION_E2E_PROVIDER=claude-cli go test ./cmd/klarion -run TestMCPRealProviderVerdict -v
//
// KLARION_E2E_PROVIDER names the provider to use (claude-cli, anthropic, openai,
// ollama). Leave it unset to use the operator's own config: KLARION_CONFIG, or
// .klarion.toml discovered from the repository, exactly as the CLI resolves it.
func TestMCPRealProviderVerdict(t *testing.T) {
	if os.Getenv("KLARION_E2E_AI") != "1" {
		t.Skip("set KLARION_E2E_AI=1 (and a provider) to run the model path")
	}
	bin, err := buildKlarion()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"mcp"}
	if p := os.Getenv("KLARION_E2E_PROVIDER"); p != "" {
		cfg := filepath.Join(t.TempDir(), "klarion.toml")
		if err := os.WriteFile(cfg, []byte("[ai]\nmode = \"on\"\nprovider = \""+p+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--config", cfg)
	}
	cmd := exec.Command(bin, args...)
	// No cmd.Dir override: the server resolves configuration from this
	// repository the way it would for the operator. A temp directory here would
	// throw that away and fall back to the default provider.
	cmd.Env = os.Environ() // the operator's real provider configuration
	s := &session{t: t, cmd: cmd, stderr: &bytes.Buffer{}, nextID: 1,
		lines: make(chan string, 64), exited: make(chan struct{})}
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = s.stderr
	s.stdin = stdin
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
		for sc.Scan() {
			s.lines <- sc.Text()
		}
		close(s.lines)
	}()
	go func() { s.waitErr = cmd.Wait(); close(s.exited) }()
	t.Cleanup(func() { _ = stdin.Close(); s.waitExit(5 * time.Second) })
	t.Cleanup(func() {
		// A model path that cannot reach a model is a configuration problem, not
		// a product bug. Say what to set rather than leaving a bare failure.
		if t.Failed() && strings.Contains(s.stderr.String(), "unavailable") {
			t.Log("hint: set KLARION_E2E_PROVIDER=claude-cli (or anthropic, openai, ollama), " +
				"or point KLARION_CONFIG at a config that names a provider")
		}
	})

	s.handshake()
	res, isErr, raw := s.callTool("scan_text", map[string]any{
		"content":  fmt.Sprintf("import stripe\nstripe.api_key = %q\n", stripeKey),
		"filename": "billing/client.py",
	})
	if isErr || res.Count == 0 {
		t.Fatalf("no finding from the model path: %s", truncate(raw, 400))
	}
	v := res.Findings[0].Verdict
	if v.Verifier == "" || v.Verifier == "heuristic" {
		t.Errorf("verifier = %q, want the configured provider", v.Verifier)
	}
	if v.Status == "" {
		t.Error("no verdict status from the model")
	}
	t.Logf("model verdict: %+v", v)

	// The claim the product is sold on: the model clears identifiers that
	// entropy cannot.
	clean, _, rawClean := s.callTool("scan_text", map[string]any{
		"content": cleanGoCode, "filename": "s3/attrs.go",
	})
	if !clean.Clean || clean.Count != 0 {
		t.Errorf("model left %d finding(s) on clean Go identifiers: %s", clean.Count, truncate(rawClean, 500))
	}
}
