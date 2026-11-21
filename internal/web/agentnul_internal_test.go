package web

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
	"github.com/max-zit/rmmzit/internal/testdb"
)

// An inventory with NUL characters (registry values often end with one) is
// saved without them instead of failing as a whole; numbers stay as sent.
func TestInventoryWithNUL(t *testing.T) {
	raw := `{"t":"inventory","d":{"hostname":"srv\u0000","software":[{"name":"Tool\u0000","version":"1.0\u0000"},{"name":"Other"}],"memory_bytes":17179869184}}`
	var env proto.Envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatal(err)
	}
	m, err := decodeAgentMessage(env)
	if err != nil {
		t.Fatal(err)
	}
	if m.Inventory.Hostname != "srv" || m.Inventory.Software[0].Name != "Tool" || m.Inventory.Software[0].Version != "1.0" || len(m.Inventory.Software) != 2 {
		t.Fatalf("decoded %+v", m.Inventory)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c, _ := st.CreateCustomer(ctx, "NUL Ltd", "")
	site, _ := st.CreateSite(ctx, c, "Main", "", "")
	tok, err := st.CreateEnrollToken(ctx, site, "t", "admin", time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	d, err := st.EnrollDevice(ctx, tok, []byte(strings.Repeat("k", 32)), "srv", "Windows", "0.13.7", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveInventory(ctx, d.ID, m.Inventory); err != nil {
		t.Fatalf("inventory not saved: %v", err)
	}
	got, err := st.Device(ctx, d.ID)
	if err != nil || got.Inventory == nil || len(got.Inventory.Software) != 2 || got.Inventory.Software[0].Name != "Tool" {
		t.Fatalf("stored inventory %+v %v", got, err)
	}
}
