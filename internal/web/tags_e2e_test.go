package web_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/max-zit/rmmzit/internal/store"
)

// Tags and dynamic groups: technicians tag devices (one by one and in the
// device list), the list filters by tag, a saved search is a group whose
// members follow the devices, scripts run on the devices of a tag, only
// administrators assign policies to tags, and Settings → Tags renames and
// deletes (with the tag's policy assignment).
func TestTagsAndGroups(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	a := e.device(t, "srv-one", "Microsoft Windows Server 2022")
	b := e.device(t, "srv-two", "Microsoft Windows Server 2016")
	c := e.device(t, "desk-one", "Microsoft Windows 11 Pro")
	tech := e.signedIn(t, admin, "tagtech", "technician", "192.168.1.41")
	ro := e.signedIn(t, admin, "tagro", "readonly", "192.168.1.42")

	// A technician tags one device on its page (the tag is made on the fly).
	if r := tech.post("/devices/"+itoa(a.ID)+"/tags", "name", "  Servers  "); r.code != http.StatusSeeOther {
		t.Fatalf("tag a device: %d", r.code)
	}
	tags, _ := e.st.Tags(ctx)
	if len(tags) != 1 || tags[0].Name != "Servers" || tags[0].Devices != 1 {
		t.Fatalf("tags after the first one: %+v", tags)
	}
	tid := itoa(tags[0].ID)
	// The same name in other letters is the same tag; a bad name is refused.
	tech.post("/devices/"+itoa(b.ID)+"/tags", "name", "servers")
	if tags, _ = e.st.Tags(ctx); len(tags) != 1 || tags[0].Devices != 2 {
		t.Fatalf("case-insensitive tag: %+v", tags)
	}
	for _, bad := range []string{"", "   ", "a,b", strings.Repeat("x", 41), "bell\x07"} {
		tech.post("/devices/"+itoa(c.ID)+"/tags", "name", bad)
	}
	if tags, _ = e.st.Tags(ctx); len(tags) != 1 {
		t.Fatalf("a bad tag name was accepted: %+v", tags)
	}
	// Read-only users see tags but cannot change them.
	if b := ro.get("/devices/" + itoa(a.ID)).body; !strings.Contains(b, ">Servers</a>") || strings.Contains(b, `/tags" class="tag-add"`) {
		t.Fatal("read-only device page: tags")
	}
	if c := ro.post("/devices/"+itoa(c.ID)+"/tags", "name", "x").code; c != http.StatusForbidden {
		t.Fatalf("read-only tag: %d", c)
	}

	// The device list filters by tag and shows the tags.
	r := tech.get("/devices?tag=" + tid)
	if !strings.Contains(r.body, "srv-one") || !strings.Contains(r.body, "srv-two") || strings.Contains(r.body, "desk-one") {
		t.Fatal("tag filter")
	}
	// Bulk: add a second tag to two devices, remove it from one.
	tech.post("/devices/bulk", "action", "tag-add", "tagname", "Office", "ids", itoa(b.ID), "ids", itoa(c.ID))
	tech.post("/devices/bulk", "action", "tag-remove", "tagname", "office", "ids", itoa(b.ID))
	byName := map[string]int{}
	tags, _ = e.st.Tags(ctx)
	for _, x := range tags {
		byName[x.Name] = x.Devices
	}
	if byName["Office"] != 1 || byName["Servers"] != 2 {
		t.Fatalf("bulk tags: %v", byName)
	}

	// A saved search is a group; its members follow the tags.
	if r := tech.post("/device-groups", "name", "All servers", "tag", tid); r.code != http.StatusSeeOther || !strings.HasPrefix(r.loc, "/devices?group=") {
		t.Fatalf("save group: %d %s", r.code, r.loc)
	}
	groups, _ := e.st.DeviceGroups(ctx)
	if len(groups) != 1 {
		t.Fatalf("groups: %+v", groups)
	}
	gid := strconv.FormatInt(groups[0].ID, 10)
	tech.post("/devices/"+itoa(c.ID)+"/tags", "name", "Servers")
	if b := tech.get("/devices?group=" + gid).body; !strings.Contains(b, "desk-one") || !strings.Contains(b, "All servers") {
		t.Fatal("the group did not follow the new tag")
	}
	if r := tech.post("/device-groups", "name", "all SERVERS", "q", "srv"); !strings.Contains(r.loc, "/devices") {
		t.Fatalf("duplicate group: %s", r.loc)
	}
	if groups, _ = e.st.DeviceGroups(ctx); len(groups) != 1 {
		t.Fatal("a second group with the same name was saved")
	}
	if c := ro.post("/device-groups", "name", "ro group", "tag", tid).code; c != http.StatusForbidden {
		t.Fatalf("read-only group: %d", c)
	}

	// A script runs on the devices of a tag (three now).
	r = admin.post("/scripts/new", "name", "Tag check", "shell", "cmd", "timeout", "60", "script", "ver", "description", "")
	sid := strings.TrimPrefix(r.loc, "/scripts/")
	if r := tech.post("/scripts/"+sid+"/run", "tag", tid); !strings.HasPrefix(r.loc, "/jobs/") {
		t.Fatalf("run on a tag: %d %s", r.code, r.loc)
	} else {
		jid, _ := strconv.ParseInt(strings.TrimPrefix(r.loc, "/jobs/"), 10, 64)
		if j, err := e.st.Job(ctx, jid); err != nil || j.Total != 3 {
			t.Fatalf("job on a tag: %+v %v", j, err)
		}
	}

	// Policies: only administrators assign them to tags.
	r = admin.post("/policies/new", "name", "Server policy", "customer", "0", "updates_set", "1", "mode", "security", "day", "2", "hour", "4")
	pid := strings.TrimPrefix(r.loc, "/policies/")
	if !strings.Contains(admin.get("/policies/"+pid).body, `value="tag:`+tid+`"`) {
		t.Fatal("the policy page offers no tags")
	}
	admin.post("/policies/"+pid+"/assign", "target", "tag:"+tid)
	if as := tagAssignments(t, e, pid); len(as) != 1 || as[0].TargetType != "tag" || as[0].Name != "Servers" {
		t.Fatalf("tag assignment: %+v", as)
	}
	if b := admin.get("/devices/" + itoa(a.ID) + "/policy").body; !strings.Contains(b, "assigned to a tag of the device") {
		t.Fatal("the device does not take the tag's policy")
	}
	// A technician's own customer policy cannot go on a tag.
	r = tech.post("/policies/new", "name", "Tech policy", "customer", itoa(a.CustomerID))
	tpid := strings.TrimPrefix(r.loc, "/policies/")
	if strings.Contains(tech.get("/policies/"+tpid).body, `value="tag:`) {
		t.Fatal("a technician is offered tags")
	}
	tech.post("/policies/"+tpid+"/assign", "target", "tag:"+tid)
	if as := tagAssignments(t, e, tpid); len(as) != 0 {
		t.Fatalf("a technician assigned a policy to a tag: %+v", as)
	}

	// Settings → Tags: administrators only; rename, then delete (the policy
	// assignment goes with it).
	if c := tech.get("/settings/tags").code; c != http.StatusForbidden {
		t.Fatalf("technician on Settings → Tags: %d", c)
	}
	admin.post("/settings/tags/"+tid, "action", "rename", "name", "Office")
	if n, _ := e.st.TagByID(ctx, mustID(t, tid)); n.Name != "Servers" {
		t.Fatal("renamed onto another tag's name")
	}
	admin.post("/settings/tags/"+tid, "action", "rename", "name", "Production servers")
	if n, _ := e.st.TagByID(ctx, mustID(t, tid)); n.Name != "Production servers" {
		t.Fatalf("rename: %+v", n)
	}
	admin.post("/settings/tags/"+tid, "action", "delete")
	if _, err := e.st.TagByID(ctx, mustID(t, tid)); err == nil {
		t.Fatal("tag not deleted")
	}
	if as := tagAssignments(t, e, pid); len(as) != 0 {
		t.Fatalf("the deleted tag's policy assignment stayed: %+v", as)
	}
	if b := admin.get("/audit").body; !strings.Contains(b, "tag.delete") || !strings.Contains(b, "group.create") || !strings.Contains(b, "device.tag") {
		t.Fatal("tag changes not audited")
	}
	// The group creator (or an administrator) deletes the group.
	if c := ro.post("/device-groups/" + gid + "/delete").code; c != http.StatusForbidden {
		t.Fatalf("read-only deletes a group: %d", c)
	}
	tech.post("/device-groups/" + gid + "/delete")
	if groups, _ = e.st.DeviceGroups(ctx); len(groups) != 0 {
		t.Fatal("group not deleted by its creator")
	}
}

func mustID(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func tagAssignments(t *testing.T, e *env, pid string) []store.Assignment {
	t.Helper()
	as, err := e.st.PolicyAssignments(context.Background(), mustID(t, pid))
	if err != nil {
		t.Fatal(err)
	}
	return as
}
