package web

import (
	"context"
	"encoding/csv"
	"net/http"
	"strconv"

	"github.com/max-zit/rmmzit/internal/store"
)

// jobCSV is the result of every device of a job as a CSV file.
func (s *Server) jobCSV(w http.ResponseWriter, r *http.Request, j *store.ScriptJob, devs []store.JobDevice) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="rmmzit-job-`+strconv.FormatInt(j.ID, 10)+`.csv"`)
	c := csv.NewWriter(w)
	_ = c.Write([]string{"device_id", "device", "customer", "site", "status", "exit_code", "timed_out", "error", "updated_at"})
	for _, d := range devs {
		code := ""
		if d.ExitCode != nil {
			code = strconv.Itoa(*d.ExitCode)
		}
		row := []string{strconv.FormatInt(d.DeviceID, 10), d.Hostname, d.Customer, d.Site, d.Status, code,
			strconv.FormatBool(d.TimedOut), d.Error, fmtTime(&d.UpdatedAt)}
		for i := range row {
			row[i] = csvCell(row[i])
		}
		_ = c.Write(row)
	}
	c.Flush()
	s.audit(r, "job.export", "job:"+strconv.FormatInt(j.ID, 10), "exported the results of job #%d (%d devices) as CSV", j.ID, len(devs))
}

// handleJobRerun runs a job again on its devices that failed or expired, as
// a new job: with the current version of its library script (the fix is
// usually why it runs again), or its own copy when the script is gone.
func (s *Server) handleJobRerun(w http.ResponseWriter, r *http.Request) {
	j := s.jobFor(w, r)
	if j == nil {
		return
	}
	u := userFrom(r)
	back := "/jobs/" + strconv.FormatInt(j.ID, 10)
	devs, err := s.store.JobDevices(r.Context(), j.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var t store.ScriptTarget
	for _, d := range devs {
		if d.Status == "failed" || d.Status == "expired" {
			t.Devices = append(t.Devices, d.DeviceID)
		}
	}
	var ids []int64
	if len(t.Devices) > 0 {
		// Only devices the user may still see.
		if ids, err = s.store.ResolveTarget(r.Context(), u, t); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if len(ids) == 0 {
		s.redirect(w, r, back, "No device of this job failed or expired.")
		return
	}
	nj := &store.ScriptJob{Name: j.Name, Shell: j.Shell, Body: j.Body, Timeout: j.Timeout, CreatedBy: u.Username, ExpiresAt: s.now().Add(jobLifetime)}
	if j.ScriptID != nil {
		if x, err := s.store.LibScript(r.Context(), *j.ScriptID); err == nil {
			sid := x.ID
			nj.ScriptID, nj.Name, nj.Shell, nj.Body, nj.Timeout = &sid, x.Name, x.Shell, x.Body, x.Timeout
		}
	}
	if err := s.store.CreateJob(r.Context(), nj, ids); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "job.create", "job:"+strconv.FormatInt(nj.ID, 10), "run %q again on %d devices that failed or expired in job #%d", nj.Name, len(ids), j.ID)
	go s.DispatchJobs(context.Background()) // #nosec G118 -- the job runs after the page has answered
	s.redirect(w, r, "/jobs/"+strconv.FormatInt(nj.ID, 10), "")
}
