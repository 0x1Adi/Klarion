package git

import (
	"testing"

	"github.com/0x1Adi/Klarion/internal/detect"
)

func TestParseUnifiedDiff(t *testing.T) {
	tests := []struct {
		name string
		diff string
		want []FileDiff
	}{
		{
			name: "single hunk, single added line",
			diff: "diff --git a/config.go b/config.go\n" +
				"index e69de29..0f3a1b2 100644\n" +
				"--- a/config.go\n" +
				"+++ b/config.go\n" +
				"@@ -0,0 +1 @@\n" +
				"+var token = \"abc\"\n",
			want: []FileDiff{{
				Path: "config.go",
				Added: []detect.Line{
					{Number: 1, Text: `var token = "abc"`},
				},
			}},
		},
		{
			name: "added lines interleaved with removed and context",
			diff: "diff --git a/app.py b/app.py\n" +
				"--- a/app.py\n" +
				"+++ b/app.py\n" +
				"@@ -1,4 +1,4 @@\n" +
				" import os\n" +
				"-old = 1\n" +
				"+new = 2\n" +
				" middle = 3\n" +
				"-gone = 4\n" +
				"+added = 5\n",
			want: []FileDiff{{
				Path: "app.py",
				Added: []detect.Line{
					// line 1 = "import os" (context), line 2 = new
					{Number: 2, Text: "new = 2"},
					// line 3 = "middle = 3" (context), line 4 = added
					{Number: 4, Text: "added = 5"},
				},
			}},
		},
		{
			name: "multiple hunks in one file",
			diff: "diff --git a/main.go b/main.go\n" +
				"--- a/main.go\n" +
				"+++ b/main.go\n" +
				"@@ -1,2 +1,3 @@\n" +
				" package main\n" +
				"+// header\n" +
				" \n" +
				"@@ -10,0 +12,2 @@\n" +
				"+const A = 1\n" +
				"+const B = 2\n",
			want: []FileDiff{{
				Path: "main.go",
				Added: []detect.Line{
					{Number: 2, Text: "// header"},
					{Number: 12, Text: "const A = 1"},
					{Number: 13, Text: "const B = 2"},
				},
			}},
		},
		{
			name: "new file",
			diff: "diff --git a/secrets.env b/secrets.env\n" +
				"new file mode 100644\n" +
				"index 0000000..abc1234\n" +
				"--- /dev/null\n" +
				"+++ b/secrets.env\n" +
				"@@ -0,0 +1,2 @@\n" +
				"+API_KEY=sk-123\n" +
				"+DB_PASS=hunter2\n",
			want: []FileDiff{{
				Path: "secrets.env",
				Added: []detect.Line{
					{Number: 1, Text: "API_KEY=sk-123"},
					{Number: 2, Text: "DB_PASS=hunter2"},
				},
			}},
		},
		{
			name: "deleted file yields nothing",
			diff: "diff --git a/old.txt b/old.txt\n" +
				"deleted file mode 100644\n" +
				"index abc1234..0000000\n" +
				"--- a/old.txt\n" +
				"+++ /dev/null\n" +
				"@@ -1,2 +0,0 @@\n" +
				"-line one\n" +
				"-line two\n",
			want: nil,
		},
		{
			name: "pure rename, no content",
			diff: "diff --git a/old/name.go b/new/name.go\n" +
				"similarity index 100%\n" +
				"rename from old/name.go\n" +
				"rename to new/name.go\n",
			want: nil, // no added lines -> flushed away
		},
		{
			name: "rename with modification",
			diff: "diff --git a/old.go b/new.go\n" +
				"similarity index 80%\n" +
				"rename from old.go\n" +
				"rename to new.go\n" +
				"--- a/old.go\n" +
				"+++ b/new.go\n" +
				"@@ -5,0 +6 @@\n" +
				"+secret := \"xyz\"\n",
			want: []FileDiff{{
				Path: "new.go",
				Added: []detect.Line{
					{Number: 6, Text: `secret := "xyz"`},
				},
			}},
		},
		{
			name: "binary diff is ignored",
			diff: "diff --git a/logo.png b/logo.png\n" +
				"index 1111111..2222222 100644\n" +
				"Binary files a/logo.png and b/logo.png differ\n",
			want: nil,
		},
		{
			name: "two files in one diff",
			diff: "diff --git a/a.txt b/a.txt\n" +
				"--- a/a.txt\n" +
				"+++ b/a.txt\n" +
				"@@ -0,0 +1 @@\n" +
				"+alpha\n" +
				"diff --git a/b.txt b/b.txt\n" +
				"--- a/b.txt\n" +
				"+++ b/b.txt\n" +
				"@@ -0,0 +1 @@\n" +
				"+beta\n",
			want: []FileDiff{
				{Path: "a.txt", Added: []detect.Line{{Number: 1, Text: "alpha"}}},
				{Path: "b.txt", Added: []detect.Line{{Number: 1, Text: "beta"}}},
			},
		},
		{
			name: "empty added line preserves numbering",
			diff: "diff --git a/f.txt b/f.txt\n" +
				"--- a/f.txt\n" +
				"+++ b/f.txt\n" +
				"@@ -0,0 +1,3 @@\n" +
				"+first\n" +
				"+\n" +
				"+third\n",
			want: []FileDiff{{
				Path: "f.txt",
				Added: []detect.Line{
					{Number: 1, Text: "first"},
					{Number: 2, Text: ""},
					{Number: 3, Text: "third"},
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseUnifiedDiff(tt.diff)
			assertFileDiffs(t, got, tt.want)
		})
	}
}

func assertFileDiffs(t *testing.T, got, want []FileDiff) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("file count: got %d %+v, want %d %+v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i].Path != want[i].Path {
			t.Errorf("file[%d] path: got %q, want %q", i, got[i].Path, want[i].Path)
		}
		if len(got[i].Added) != len(want[i].Added) {
			t.Fatalf("file[%d] %q added count: got %d %+v, want %d %+v",
				i, want[i].Path, len(got[i].Added), got[i].Added,
				len(want[i].Added), want[i].Added)
		}
		for j := range want[i].Added {
			g, w := got[i].Added[j], want[i].Added[j]
			if g.Number != w.Number || g.Text != w.Text {
				t.Errorf("file[%d] %q line[%d]: got {%d,%q}, want {%d,%q}",
					i, want[i].Path, j, g.Number, g.Text, w.Number, w.Text)
			}
		}
	}
}

func TestPathFromDiffGit(t *testing.T) {
	tests := []struct {
		line     string
		wantPath string
		wantOK   bool
	}{
		{"diff --git a/foo.go b/foo.go", "foo.go", true},
		{"diff --git a/old.go b/new.go", "new.go", true},
		{"diff --git a/dir/x.go b/dir/x.go", "dir/x.go", true},
		{"diff --git nonsense", "", false},
	}
	for _, tt := range tests {
		p, ok := pathFromDiffGit(tt.line)
		if ok != tt.wantOK || p != tt.wantPath {
			t.Errorf("pathFromDiffGit(%q) = (%q,%v), want (%q,%v)",
				tt.line, p, ok, tt.wantPath, tt.wantOK)
		}
	}
}

// A merge's combined diff (--cc) carries one marker column per parent. Only a
// line that is new against every parent is content the merge itself added.
func TestParseCombinedDiff(t *testing.T) {
	diff := "diff --cc a.txt\n" +
		"index 1111111,2222222..3333333\n" +
		"--- a/a.txt\n" +
		"+++ b/a.txt\n" +
		"@@@ -1,2 -1,2 +1,3 @@@\n" +
		" +main\n" +
		"- gone-from-result\n" +
		"+ side\n" +
		"++evil = merged-in-resolution\n" +
		"diff --git a/b.txt b/b.txt\n" +
		"--- a/b.txt\n" +
		"+++ b/b.txt\n" +
		"@@ -0,0 +1 @@\n" +
		"+plain = after-merge\n"
	assertFileDiffs(t, ParseUnifiedDiff(diff), []FileDiff{
		{Path: "a.txt", Added: []detect.Line{{Number: 3, Text: "evil = merged-in-resolution"}}},
		{Path: "b.txt", Added: []detect.Line{{Number: 1, Text: "plain = after-merge"}}},
	})
}
