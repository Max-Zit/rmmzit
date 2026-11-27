-- The recent outcome of each library script on each device, kept as the
-- runs of jobs end: the "Script failed" alert rule reads this small table
-- instead of the whole job history. failed counts failed runs since the
-- last good one; missed counts failed and expired runs since then.
CREATE TABLE script_streaks (
    device_id   bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    script_id   bigint NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    name        text NOT NULL,
    failed      int NOT NULL DEFAULT 0,
    missed      int NOT NULL DEFAULT 0,
    last_status text NOT NULL,
    job_id      bigint,
    run_id      bigint REFERENCES script_runs(id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL,
    PRIMARY KEY (device_id, script_id)
);
CREATE INDEX script_streaks_open ON script_streaks(device_id) WHERE missed > 0;
