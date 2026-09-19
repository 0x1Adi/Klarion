package verify

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// stubCommand writes a judge script that ignores stdin and prints stdout.
func stubCommand(t *testing.T, stdout string, exitCode int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "judge")
	script := "#!/bin/sh\ncat > /dev/null\nprintf '%s' " + shellQuote(stdout) + "\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCommandVerifyMapsResultsAndDefaultsMissing(t *testing.T) {
	path := stubCommand(t, `{"results":[{"index":0,"status":"secret","confidence":0.9,"reason":"live"}]}`, 0)
	v := newCommand(&config.AIConfig{Command: path})
	got, err := v.Verify(context.Background(), []Request{{Secret: "a"}, {Secret: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Status != finding.VerdictSecret || got[0].Confidence != 0.9 {
		t.Fatalf("index 0: %+v", got[0])
	}
	// A verdict the judge never returned must not become "safe".
	if got[1].Status != finding.VerdictUncertain || got[1].Reason != noVerdictReason {
		t.Fatalf("index 1: %+v", got[1])
	}
}

func TestCommandVerifyFailureIsAnError(t *testing.T) {
	path := stubCommand(t, "", 1)
	v := newCommand(&config.AIConfig{Command: path})
	if _, err := v.Verify(context.Background(), []Request{{Secret: "a"}}); err == nil {
		t.Fatal("expected error from nonzero exit")
	}
}

func TestBuildCommandProvider(t *testing.T) {
	path := stubCommand(t, "{}", 0)
	v, err := Build(&config.AIConfig{Mode: "on", Provider: "command", Command: path + " --flag"})
	if err != nil {
		t.Fatal(err)
	}
	if v == nil {
		t.Fatal("nil verifier")
	}
	if _, err := Build(&config.AIConfig{Mode: "on", Provider: "command"}); err == nil {
		t.Fatal("empty ai.command must fail in mode=on")
	}
}
