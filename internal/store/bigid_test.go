package store_test

import (
	"context"
	"math"
	"testing"

	"github.com/max-zit/rmmzit/internal/store"
)

// Filters take any 64-bit id: one beyond the 32-bit range (from a URL, for
// example) finds nothing instead of a database error (an untyped "$1 = 0"
// made PostgreSQL read the parameter as a 32-bit integer).
func TestFiltersTakeBigIDs(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	admin := &store.User{Role: store.RoleAdmin}
	for _, id := range []int64{math.MaxInt64, 1 << 40} {
		if l, err := s.Devices(ctx, admin, store.DeviceFilter{CustomerID: id, SiteID: id}); err != nil || len(l) != 0 {
			t.Errorf("Devices: %v %v", l, err)
		}
		if l, err := s.Alerts(ctx, admin, store.AlertFilter{DeviceID: id}); err != nil || len(l) != 0 {
			t.Errorf("Alerts: %v %v", l, err)
		}
		if _, err := s.AuditEntries(ctx, store.AuditFilter{Before: id}); err != nil {
			t.Errorf("AuditEntries: %v", err)
		}
		if _, err := s.NetChecks(ctx, id); err != nil {
			t.Errorf("NetChecks: %v", err)
		}
		if _, err := s.DiskHealth(ctx, id); err != nil {
			t.Errorf("DiskHealth: %v", err)
		}
		if _, err := s.Jobs(ctx, "", id, 10); err != nil {
			t.Errorf("Jobs: %v", err)
		}
		if _, err := s.Schedules(ctx, id); err != nil {
			t.Errorf("Schedules: %v", err)
		}
		if _, err := s.MonitorResults(ctx, id); err != nil {
			t.Errorf("MonitorResults: %v", err)
		}
		if _, err := s.DeviceVulns(ctx, id); err != nil {
			t.Errorf("DeviceVulns: %v", err)
		}
	}
}
