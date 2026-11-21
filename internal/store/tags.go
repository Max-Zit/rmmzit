package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Tag names a group of devices; scripts and policies can target it.
type Tag struct {
	ID      int64
	Name    string
	Devices int // how many devices carry it (Tags only)
}

// MaxTagName is the longest tag or group name.
const MaxTagName = 40

// ErrBadTagName is returned for an empty, too long or odd name.
var ErrBadTagName = errors.New("a name has 1 to 40 characters, without commas or line breaks")

// CleanTagName checks and normalizes a tag or group name (inner spaces
// collapse to one).
func CleanTagName(name string) (string, error) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > MaxTagName || strings.Contains(name, ",") {
		return "", ErrBadTagName
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", ErrBadTagName
		}
	}
	return name, nil
}

// Tags lists the tags a user may see with their device counts, by name.
// Administrators and users of all customers (and u == nil) see every tag; a
// user of some customers sees only the tags on devices of those customers,
// counting only those devices: a tag name can say something about another
// customer.
func (s *Store) Tags(ctx context.Context, u *User) ([]Tag, error) {
	q := `SELECT t.id, t.name, count(dt.device_id) FROM tags t LEFT JOIN device_tags dt ON dt.tag_id=t.id
		GROUP BY t.id ORDER BY lower(t.name)`
	var args []any
	if !seesAllCustomers(u) {
		q = `SELECT t.id, t.name, count(DISTINCT d.id) FROM tags t JOIN device_tags dt ON dt.tag_id=t.id
		JOIN devices d ON d.id=dt.device_id JOIN sites x ON x.id=d.site_id
		WHERE x.customer_id IN (SELECT customer_id FROM user_customers WHERE user_id=$1)
		GROUP BY t.id ORDER BY lower(t.name)`
		args = append(args, u.ID)
	}
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tag
	for rows.Next() {
		var t Tag
		if err := rows.Scan(&t.ID, &t.Name, &t.Devices); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TagByID returns one tag.
func (s *Store) TagByID(ctx context.Context, id int64) (*Tag, error) {
	t := &Tag{}
	err := s.db.QueryRow(ctx, `SELECT id, name FROM tags WHERE id=$1`, id).Scan(&t.ID, &t.Name)
	return t, notFound(err)
}

// EnsureTag returns the tag of a name, creating it when it is new (created
// reports that).
func (s *Store) EnsureTag(ctx context.Context, name, by string) (t *Tag, created bool, err error) {
	name, err = CleanTagName(name)
	if err != nil {
		return nil, false, err
	}
	t = &Tag{}
	err = s.db.QueryRow(ctx, `SELECT id, name FROM tags WHERE lower(name)=lower($1)`, name).Scan(&t.ID, &t.Name)
	if err == nil {
		return t, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	err = s.db.QueryRow(ctx, `INSERT INTO tags(name, created_by, created_at) VALUES($1,$2,$3)
		ON CONFLICT (lower(name)) DO UPDATE SET name=tags.name RETURNING id, name`, name, by, s.now()).Scan(&t.ID, &t.Name)
	if err != nil {
		return nil, false, err
	}
	return t, true, nil
}

// RenameTag changes a tag's name (ErrConflict: another tag has it).
func (s *Store) RenameTag(ctx context.Context, id int64, name string) error {
	name, err := CleanTagName(name)
	if err != nil {
		return err
	}
	var other int64
	if err := s.db.QueryRow(ctx, `SELECT id FROM tags WHERE lower(name)=lower($1) AND id<>$2`, name, id).Scan(&other); err == nil {
		return ErrConflict
	}
	tag, err := s.db.Exec(ctx, `UPDATE tags SET name=$2 WHERE id=$1`, id, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteTag removes a tag from all devices, with its policy assignment.
func (s *Store) DeleteTag(ctx context.Context, id int64) error {
	defer s.scopesChanged()
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM policy_assignments WHERE target_type='tag' AND target_id=$1`, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM tags WHERE id=$1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// SetDeviceTag adds (on) or removes a tag on devices.
func (s *Store) SetDeviceTag(ctx context.Context, tagID int64, deviceIDs []int64, on bool) error {
	defer s.scopesChanged()
	if on {
		_, err := s.db.Exec(ctx, `INSERT INTO device_tags(device_id, tag_id) SELECT d.id, $1 FROM devices d WHERE d.id = ANY($2::bigint[])
			ON CONFLICT DO NOTHING`, tagID, deviceIDs)
		return err
	}
	_, err := s.db.Exec(ctx, `DELETE FROM device_tags WHERE tag_id=$1 AND device_id = ANY($2::bigint[])`, tagID, deviceIDs)
	return err
}

// DeviceTags returns the tags of every device that has some, by name.
func (s *Store) DeviceTags(ctx context.Context) (map[int64][]Tag, error) {
	rows, err := s.db.Query(ctx, `SELECT dt.device_id, t.id, t.name FROM device_tags dt JOIN tags t ON t.id=dt.tag_id ORDER BY dt.device_id, lower(t.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]Tag{}
	for rows.Next() {
		var id int64
		var t Tag
		if err := rows.Scan(&id, &t.ID, &t.Name); err != nil {
			return nil, err
		}
		out[id] = append(out[id], t)
	}
	return out, rows.Err()
}

// TagsOf returns the tags of one device, by name.
func (s *Store) TagsOf(ctx context.Context, deviceID int64) ([]Tag, error) {
	rows, err := s.db.Query(ctx, `SELECT t.id, t.name FROM device_tags dt JOIN tags t ON t.id=dt.tag_id WHERE dt.device_id=$1 ORDER BY lower(t.name)`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tag
	for rows.Next() {
		var t Tag
		if err := rows.Scan(&t.ID, &t.Name); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeviceGroup is a dynamic group: a saved filter of the device list.
type DeviceGroup struct {
	ID        int64
	Name      string
	Filter    json.RawMessage
	CreatedBy string
	CreatedAt time.Time
}

// DeviceGroups lists the groups by name.
func (s *Store) DeviceGroups(ctx context.Context, u *User) ([]DeviceGroup, error) {
	q := `SELECT id, name, filter, created_by, created_at FROM device_groups`
	var args []any
	if !seesAllCustomers(u) {
		q += ` WHERE ` + groupVisible + `$1)`
		args = append(args, u.Username)
	}
	rows, err := s.db.Query(ctx, q+` ORDER BY lower(name)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceGroup
	for rows.Next() {
		var g DeviceGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Filter, &g.CreatedBy, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeviceGroup returns one group the user may see (ErrNotFound otherwise).
func (s *Store) DeviceGroup(ctx context.Context, u *User, id int64) (*DeviceGroup, error) {
	g := &DeviceGroup{}
	q := `SELECT id, name, filter, created_by, created_at FROM device_groups WHERE id=$1`
	args := []any{id}
	if !seesAllCustomers(u) {
		q += ` AND ` + groupVisible + `$2)`
		args = append(args, u.Username)
	}
	err := s.db.QueryRow(ctx, q, args...).Scan(&g.ID, &g.Name, &g.Filter, &g.CreatedBy, &g.CreatedAt)
	return g, notFound(err)
}

// seesAllCustomers: administrators, users of all customers and the system
// (u == nil).
func seesAllCustomers(u *User) bool {
	return u == nil || u.IsAdmin() || u.AllCustomers
}

// groupVisible (followed by the placeholder of the user name) limits the
// saved device groups a user of some customers sees to those saved by
// administrators, by users of all customers and by the user: a group's name
// can say something about another customer.
const groupVisible = `(created_by IN (SELECT username FROM users WHERE role='admin' OR all_customers) OR created_by=`

// SaveDeviceGroup creates a group (ErrConflict: the name is taken).
func (s *Store) SaveDeviceGroup(ctx context.Context, name string, filter json.RawMessage, by string) (int64, error) {
	name, err := CleanTagName(name)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRow(ctx, `INSERT INTO device_groups(name, filter, created_by, created_at) VALUES($1,$2,$3,$4)
		ON CONFLICT (lower(name)) DO NOTHING RETURNING id`, name, filter, by, s.now()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrConflict
	}
	return id, err
}

// DeleteDeviceGroup removes a group.
func (s *Store) DeleteDeviceGroup(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM device_groups WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// TagByName returns the tag of a name (case does not count).
func (s *Store) TagByName(ctx context.Context, name string) (*Tag, error) {
	t := &Tag{}
	err := s.db.QueryRow(ctx, `SELECT id, name FROM tags WHERE lower(name)=lower($1)`, strings.Join(strings.Fields(name), " ")).Scan(&t.ID, &t.Name)
	return t, notFound(err)
}
