package web_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/store"
	"github.com/max-zit/rmmzit/internal/web"
)

// Script failed (issue #17): a library script that fails in jobs opens an
// alert under the device's policy, after N failures in a row, optionally
// counting expired runs, and the alert resolves after a good run.
func TestScriptFailedAlert(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	kiosk := e.device(t, "kiosk-17", "Debian GNU/Linux 13 (trixie)")
	otherCust, _ := e.st.CreateCustomer(ctx, "Without the rule", "")
	other := e.deviceIn(t, otherCust, "no-rule")
	x := &store.LibScript{Name: "Hourly health check", Shell: "bash", Body: "exit 3", Timeout: 60, UpdatedBy: "admin"}
	if err := e.st.SaveLibScript(ctx, x); err != nil {
		t.Fatal(err)
	}
	rules := []string{"name", "Kiosks", "alerts_set", "1", "cpu_percent", "90", "cpu_minutes", "15", "mem_percent", "90",
		"mem_minutes", "15", "disk_percent", "90", "disk_min_free_gb", "5", "offline_minutes", "10080", "reboot_days", "0"}
	pid := customerPolicy(t, admin, kiosk.CustomerID, append(rules, "script_failed", "1", "script_runs", "2")...)

	// run ends one run of the script on the devices: exit code (nil = the
	// run expired while the device was offline).
	jobs := 0
	run := func(exit *int, out string, devs ...*store.Device) {
		t.Helper()
		jobs++
		ids := []int64{}
		for _, d := range devs {
			ids = append(ids, d.ID)
		}
		expires := e.now.Add(time.Hour)
		if exit == nil {
			expires = e.now.Add(-time.Minute)
		}
		j := &store.ScriptJob{ScriptID: &x.ID, Name: x.Name, Shell: x.Shell, Body: x.Body, Timeout: 60, CreatedBy: "schedule", ExpiresAt: expires}
		if err := e.st.CreateJob(ctx, j, ids); err != nil {
			t.Fatal(err)
		}
		if exit == nil {
			if err := e.st.ExpireJobs(ctx, false); err != nil {
				t.Fatal(err)
			}
			return
		}
		for _, d := range devs {
			r := &store.ScriptRun{DeviceID: d.ID, Username: "schedule", Shell: "bash", Script: x.Body, StartedAt: e.now, ExitCode: exit, Output: out, JobID: &j.ID}
			if err := e.st.AddScriptRun(ctx, r); err != nil {
				t.Fatal(err)
			}
			status := "done"
			if *exit != 0 {
				status = "failed"
			}
			if err := e.st.FinishJobRun(ctx, j.ID, d.ID, status, &r.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	alerts := func() string {
		e.srv.CheckAlerts(ctx)
		return admin.get("/alerts").body
	}
	three, zero := 3, 0

	run(&three, "starting\ncannot reach http://127.0.0.1:8080/health <!channel>\n", kiosk, other)
	if b := alerts(); strings.Contains(b, "Script failed") {
		t.Fatal("an alert after one failure, the rule asks for two in a row")
	}
	run(&three, "starting\ncannot reach http://127.0.0.1:8080/health <!channel>\n", kiosk, other)
	b := alerts()
	if !strings.Contains(b, "Script failed") || !strings.Contains(b, "Hourly health check failed 2 times in a row") ||
		!strings.Contains(b, "exit code 3") || !strings.Contains(b, "cannot reach") {
		t.Fatalf("no alert after two failures: %s", b)
	}
	open, _ := e.st.Alerts(ctx, &store.User{Role: store.RoleAdmin}, store.AlertFilter{Open: true})
	for _, a := range open {
		if a.Kind == web.AlertScript && a.DeviceID == other.ID {
			t.Fatal("a device without the rule got the alert")
		}
	}

	// An expired run does not count, unless the rules say so; a good run
	// resolves the alert.
	run(nil, "", kiosk)
	run(&zero, "ok", kiosk)
	if b := alerts(); countOpen(t, e, web.AlertScript) != 0 {
		t.Fatalf("the alert stayed open after a good run: %s", b)
	}
	run(nil, "", kiosk)
	run(nil, "", kiosk)
	if countOpen(t, e, web.AlertScript) != 0 {
		t.Fatal("expired runs opened an alert without the option")
	}
	if r := admin.post("/policies/"+pid, append(rules, "script_failed", "1", "script_runs", "2", "script_expired", "1")...); r.code != 303 {
		t.Fatalf("policy update: %d %s", r.code, r.loc)
	}
	if b := alerts(); !strings.Contains(b, "did not run 2 times in a row: the device stayed offline") {
		t.Fatalf("expired runs with the option: %s", b)
	}

	// A deleted script takes its alert with it.
	if err := e.st.DeleteLibScript(ctx, x.ID); err != nil {
		t.Fatal(err)
	}
	if alerts(); countOpen(t, e, web.AlertScript) != 0 {
		t.Fatal("the alert of a deleted script stayed open")
	}
}

func countOpen(t *testing.T, e *env, kind string) int {
	t.Helper()
	list, err := e.st.Alerts(context.Background(), &store.User{Role: store.RoleAdmin}, store.AlertFilter{Open: true})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range list {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

// A job's results as CSV, and running it again where it failed or expired:
// with the current library script, only on devices the user may see.
func TestJobRerunAndCSV(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	good := e.device(t, "good-pc", "Debian GNU/Linux 13 (trixie)")
	bad := e.device(t, "bad-pc", "Debian GNU/Linux 13 (trixie)")
	gone := e.device(t, "offline-pc", "Debian GNU/Linux 13 (trixie)")
	x := &store.LibScript{Name: "Cleanup", Shell: "bash", Body: "exit 1", Timeout: 60, UpdatedBy: "admin"}
	if err := e.st.SaveLibScript(ctx, x); err != nil {
		t.Fatal(err)
	}
	j := &store.ScriptJob{ScriptID: &x.ID, Name: x.Name, Shell: x.Shell, Body: x.Body, Timeout: 60, CreatedBy: "admin", ExpiresAt: e.now.Add(time.Minute)}
	if err := e.st.CreateJob(ctx, j, []int64{good.ID, bad.ID, gone.ID}); err != nil {
		t.Fatal(err)
	}
	for d, code := range map[*store.Device]int{good: 0, bad: 1} {
		c := code
		r := &store.ScriptRun{DeviceID: d.ID, Username: "admin", Shell: "bash", Script: x.Body, StartedAt: e.now, ExitCode: &c, JobID: &j.ID}
		if err := e.st.AddScriptRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		st := map[int]string{0: "done", 1: "failed"}[c]
		if err := e.st.FinishJobRun(ctx, j.ID, d.ID, st, &r.ID); err != nil {
			t.Fatal(err)
		}
	}
	e.now = e.now.Add(2 * time.Minute)
	if err := e.st.ExpireJobs(ctx, false); err != nil {
		t.Fatal(err)
	}
	jid := itoa(j.ID)
	csvBody := admin.get("/jobs/" + jid + "?format=csv").body
	if !strings.HasPrefix(csvBody, "device_id,device,customer,site,status,exit_code,") || !strings.Contains(csvBody, ",bad-pc,") ||
		!strings.Contains(csvBody, ",failed,1,") || !strings.Contains(csvBody, ",expired,,") || !strings.Contains(csvBody, ",done,0,") {
		t.Fatalf("job CSV: %q", csvBody)
	}
	if b := admin.get("/jobs/" + jid).body; !strings.Contains(b, "Run again where it failed (2)") || !strings.Contains(b, "format=csv") {
		t.Fatal("job page: no re-run button or CSV link")
	}

	// The script was fixed meanwhile: the new job runs the fixed version.
	x.Body = "exit 0"
	if err := e.st.SaveLibScript(ctx, x); err != nil {
		t.Fatal(err)
	}
	r := admin.post("/jobs/" + jid + "/rerun")
	nid := strings.TrimPrefix(r.loc, "/jobs/")
	if r.code != 303 || nid == jid {
		t.Fatalf("re-run: %d %s", r.code, r.loc)
	}
	n, _ := strconv.ParseInt(nid, 10, 64)
	nj, err := e.st.Job(ctx, n)
	if err != nil || nj.Body != "exit 0" || nj.Total != 2 {
		t.Fatalf("new job: %+v %v", nj, err)
	}
	devs, _ := e.st.JobDevices(ctx, n)
	for _, d := range devs {
		if d.DeviceID == good.ID {
			t.Fatal("the re-run includes a device where the script succeeded")
		}
	}

	// A technician of another customer: neither the job nor its re-run.
	other, _ := e.st.CreateCustomer(ctx, "Other Ltd", "")
	e.deviceIn(t, other, "their-pc")
	tech := e.signedInFor(t, admin, "jobtech", other, "192.168.1.51")
	if c := tech.get("/jobs/" + jid + "?format=csv").code; c != 404 {
		t.Fatalf("technician read another user's job: %d", c)
	}
	if c := tech.post("/jobs/" + jid + "/rerun").code; c != 404 {
		t.Fatalf("technician re-ran another user's job: %d", c)
	}
	if !e.audited(t, "job.export") {
		t.Fatal("the export is not audited")
	}
}
