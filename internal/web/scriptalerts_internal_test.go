package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/max-zit/rmmzit/internal/store"
)

func TestScriptAlertMessage(t *testing.T) {
	two, rules := 2, MonitoringSettings{ScriptFailed: true}
	msg, open := scriptAlert(rules, store.ScriptStreak{Name: "Cleanup", Failed: 1, Missed: 1, LastStatus: "failed", JobID: 9, ExitCode: &two,
		Output: "line 1\r\nevil\u202eexe\x00 " + strings.Repeat("x", 500)})
	if !open || !strings.HasPrefix(msg, "Cleanup failed once (job #9): exit code 2. Output: …") || strings.ContainsAny(msg, "\r\n\x00\u202e") || len([]rune(msg)) > 400 {
		t.Fatalf("message %q", msg)
	}
	if _, open := scriptAlert(rules, store.ScriptStreak{Name: "x", Failed: 0, Missed: 3, LastStatus: "expired"}); open {
		t.Fatal("expired runs counted without the option")
	}
	rules.ScriptRuns = 3
	if _, open := scriptAlert(rules, store.ScriptStreak{Name: "x", Failed: 2, Missed: 2, LastStatus: "failed"}); open {
		t.Fatal("two failures opened a rule of three")
	}
}

// Alert texts reach Slack and Teams as text: what a device wrote cannot
// mention the channel or become a link.
func TestChatTextEscaped(t *testing.T) {
	ev := alertEvent{Event: "alert.opened", Severity: "warning", Title: "Script failed", Message: "x <!channel> <https://evil.example|click> [click](https://evil.example) & y"}
	b, _ := payload(ChannelSlack, []alertEvent{ev})
	var s map[string]string
	_ = json.Unmarshal(b, &s)
	if strings.ContainsAny(s["text"], "<>") || !strings.Contains(s["text"], "&lt;!channel&gt;") || !strings.Contains(s["text"], "&amp; y") {
		t.Fatalf("Slack text %q", s["text"])
	}
	if b, _ := payload(ChannelTeams, []alertEvent{ev}); strings.Contains(string(b), "](") {
		t.Fatalf("Teams text keeps a link: %s", b)
	}
}
