package web_test

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

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
	tags, _ := e.st.Tags(ctx, nil)
	if len(tags) != 1 || tags[0].Name != "Servers" || tags[0].Devices != 1 {
		t.Fatalf("tags after the first one: %+v", tags)
	}
	tid := itoa(tags[0].ID)
	// The same name in other letters is the same tag; a bad name is refused.
	tech.post("/devices/"+itoa(b.ID)+"/tags", "name", "servers")
	if tags, _ = e.st.Tags(ctx, nil); len(tags) != 1 || tags[0].Devices != 2 {
		t.Fatalf("case-insensitive tag: %+v", tags)
	}
	for _, bad := range []string{"", "   ", "a,b", strings.Repeat("x", 41), "bell\x07"} {
		tech.post("/devices/"+itoa(c.ID)+"/tags", "name", bad)
	}
	if tags, _ = e.st.Tags(ctx, nil); len(tags) != 1 {
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
	if b := deviceTable(r.body); !strings.Contains(b, "srv-one") || !strings.Contains(b, "srv-two") || strings.Contains(b, "desk-one") {
		t.Fatal("tag filter")
	}
	// Bulk: add a second tag to two devices, remove it from one.
	tech.post("/devices/bulk", "action", "tag-add", "tagname", "Office", "ids", itoa(b.ID), "ids", itoa(c.ID))
	tech.post("/devices/bulk", "action", "tag-remove", "tagname", "office", "ids", itoa(b.ID))
	byName := map[string]int{}
	tags, _ = e.st.Tags(ctx, nil)
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
	groups, _ := e.st.DeviceGroups(ctx, nil)
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
	if groups, _ = e.st.DeviceGroups(ctx, nil); len(groups) != 1 {
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
	if groups, _ = e.st.DeviceGroups(ctx, nil); len(groups) != 0 {
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

// A user of some customers sees only the tags on devices of those customers
// and only the groups saved by administrators, users of all customers or
// themselves: tag and group names can say something about another customer.
func TestTagScope(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	mine := e.device(t, "lab-pc", "Microsoft Windows 11 Pro")
	other, err := e.st.CreateCustomer(ctx, "Other Ltd", "")
	if err != nil {
		t.Fatal(err)
	}
	theirs := e.deviceIn(t, other, "other-pc")
	admin.post("/devices/"+itoa(mine.ID)+"/tags", "name", "Shared")
	admin.post("/devices/"+itoa(theirs.ID)+"/tags", "name", "Shared")
	admin.post("/devices/"+itoa(theirs.ID)+"/tags", "name", "Other secret")
	tech := e.signedInFor(t, admin, "scopetech", mine.CustomerID, "192.168.1.51")
	otherTech := e.signedInFor(t, admin, "othertech", other, "192.168.1.52")

	for _, p := range []string{"/devices", "/devices/" + itoa(mine.ID)} {
		b := tech.get(p).body
		if !strings.Contains(b, "Shared") || strings.Contains(b, "Other secret") {
			t.Fatalf("%s: a tag of another customer is shown", p)
		}
	}
	if tags, _ := e.st.Tags(ctx, nil); len(tags) != 2 {
		t.Fatalf("all tags: %+v", tags)
	}
	// Counts only the user's devices.
	users, _ := e.st.Users(ctx)
	for _, u := range users {
		if u.Username != "scopetech" {
			continue
		}
		if tags, _ := e.st.Tags(ctx, u); len(tags) != 1 || tags[0].Name != "Shared" || tags[0].Devices != 1 {
			t.Fatalf("tags of a user of one customer: %+v", tags)
		}
	}

	// Groups: the administrator's and one's own, not another customer's.
	admin.post("/device-groups", "name", "Admin group", "q", "pc")
	otherTech.post("/device-groups", "name", "Other group", "q", "other")
	groups, _ := e.st.DeviceGroups(ctx, nil)
	if len(groups) != 2 {
		t.Fatalf("groups: %+v", groups)
	}
	var otherGID string
	for _, g := range groups {
		if g.Name == "Other group" {
			otherGID = strconv.FormatInt(g.ID, 10)
		}
	}
	b := tech.get("/devices").body
	if !strings.Contains(b, "Admin group") || strings.Contains(b, "Other group") {
		t.Fatal("device groups of another customer are shown")
	}
	if b := tech.get("/devices?group=" + otherGID).body; strings.Contains(b, "Other group") {
		t.Fatal("another customer's group opens by its id")
	}
	if c := tech.post("/device-groups/" + otherGID + "/delete").code; c != http.StatusNotFound {
		t.Fatalf("delete another customer's group: %d", c)
	}

	// A policy of the user's customer on a hidden tag does not name it.
	r := admin.post("/policies/new", "name", "Lab policy", "customer", itoa(mine.CustomerID))
	pid := strings.TrimPrefix(r.loc, "/policies/")
	for _, name := range []string{"Shared", "Other secret"} {
		var tid int64
		tags, _ := e.st.Tags(ctx, nil)
		for _, x := range tags {
			if x.Name == name {
				tid = x.ID
			}
		}
		admin.post("/policies/"+pid+"/assign", "target", "tag:"+strconv.FormatInt(tid, 10))
	}
	if as := tagAssignments(t, e, pid); len(as) != 2 {
		t.Fatalf("assignments: %+v", as)
	}
	b = tech.get("/policies/" + pid).body
	if !strings.Contains(b, ">Shared</a>") || strings.Contains(b, "Other secret") {
		t.Fatal("the policy page names a tag of another customer")
	}
}

// deviceIn enrolls a device in a new site of a customer.
func (e *env) deviceIn(t *testing.T, cid int64, hostname string) *store.Device {
	t.Helper()
	ctx := context.Background()
	site, _ := e.st.CreateSite(ctx, cid, hostname+" site", "", "")
	tok, err := e.st.CreateEnrollToken(ctx, site, "test", "admin", time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	pub := bytes.Repeat([]byte{byte(len(hostname) + 7)}, 32)
	copy(pub, hostname)
	d, err := e.st.EnrollDevice(ctx, tok, pub, hostname, "", "Microsoft Windows 11 Pro", "0.8.0", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// signedInFor signs in a new technician of one customer.
func (e *env) signedInFor(t *testing.T, admin *client, name string, cid int64, ip string) *client {
	t.Helper()
	admin.post("/users", "username", name, "password", name+" password 1", "role", "technician", "customers", itoa(cid))
	c := e.client(ip)
	c.post("/login", "username", name, "password", name+" password 1")
	sec := secretRE.FindStringSubmatch(c.get("/login/enroll").body)[1]
	c.post("/login/enroll", "code", e.code(sec))
	c.post("/account/password", "current", name+" password 1", "password", name+" password 22", "password2", name+" password 22")
	return c
}
