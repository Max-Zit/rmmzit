package web

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/max-zit/rmmzit/internal/store"
)

// AlertScript is the alert of a library script that fails on a device,
// in jobs and schedules alike (issue #17).
const AlertScript = "script"

func init() { alertTitles[AlertScript] = "Script failed" }

// scriptConditions open an alert per library script whose last runs on a
// device failed (or expired, if the rules count those), when the device's
// alert rules ask for it. The alert stays open until the script runs well
// on that device again.
func (s *Server) scriptConditions(ctx context.Context, rules map[int64]MonitoringSettings) []store.Condition {
	list, err := s.store.ScriptStreaks(ctx)
	if err != nil {
		s.log.Warn("alerts: cannot read the script results", "err", err)
		return nil
	}
	var conds []store.Condition
	for _, x := range list {
		r, ok := rules[x.DeviceID]
		if !ok || !r.ScriptFailed {
			continue
		}
		if msg, open := scriptAlert(r, x); open {
			conds = append(conds, store.Condition{DeviceID: x.DeviceID, Kind: AlertScript, Key: x.Name, Severity: "warning", Message: msg})
		}
	}
	return conds
}

// scriptAlert says whether the streak opens an alert under the rules, and
// its message.
func scriptAlert(r MonitoringSettings, x store.ScriptStreak) (string, bool) {
	need := max(r.ScriptRuns, 1)
	n := x.Failed
	if r.ScriptExpired {
		n = x.Missed
	}
	if n < need || n == 0 {
		return "", false
	}
	times := "once"
	if n > 1 {
		times = fmt.Sprintf("%d times in a row", n)
	}
	if x.LastStatus == "expired" && r.ScriptExpired {
		if x.Failed == 0 {
			return fmt.Sprintf("%s did not run %s: the device stayed offline until job #%d expired", x.Name, times, x.JobID), true
		}
		return fmt.Sprintf("%s did not run well %s; the last run expired (job #%d) while the device was offline", x.Name, times, x.JobID), true
	}
	var why string
	switch {
	case x.Error != "":
		why = oneLine(x.Error, 200)
	case x.TimedOut:
		why = "time limit reached"
	case x.ExitCode != nil:
		why = fmt.Sprintf("exit code %d", *x.ExitCode)
	default:
		why = "no result"
	}
	msg := fmt.Sprintf("%s failed %s (job #%d): %s", x.Name, times, x.JobID, why)
	if out := oneLine(x.Output, 300); out != "" {
		msg += ". Output: " + out
	}
	return msg, true
}

// oneLine is the end of a device's text as one line of at most n
// characters: control and format characters (bidi overrides) become spaces.
func oneLine(s string, n int) string {
	s = strings.Join(strings.FieldsFunc(s, func(c rune) bool {
		return unicode.IsSpace(c) || unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == unicode.ReplacementChar
	}), " ")
	if r := []rune(s); len(r) > n {
		s = "…" + string(r[len(r)-n:])
	}
	return s
}
