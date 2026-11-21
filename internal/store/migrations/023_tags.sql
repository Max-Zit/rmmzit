-- Tags of devices (one name each, case does not count), and dynamic device
-- groups: saved filters of the device list, so their members change with
-- the devices. Policies can be assigned to a tag.
CREATE TABLE tags (
    id         bigserial PRIMARY KEY,
    name       text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX tags_name ON tags (lower(name));

CREATE TABLE device_tags (
    device_id bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tag_id    bigint NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, tag_id)
);
CREATE INDEX device_tags_tag ON device_tags(tag_id);

CREATE TABLE device_groups (
    id         bigserial PRIMARY KEY,
    name       text NOT NULL,
    filter     jsonb NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX device_groups_name ON device_groups (lower(name));

ALTER TABLE policy_assignments DROP CONSTRAINT policy_assignments_target_type_check;
ALTER TABLE policy_assignments ADD CONSTRAINT policy_assignments_target_type_check
    CHECK (target_type IN ('customer', 'site', 'device', 'tag'));
