-- A display name of a device, given in the console or at installation
-- (DEVICENAME= / enroll --name). Empty = the hostname the agent reports.
-- The agent never changes it, so a name chosen in the console stays.
ALTER TABLE devices ADD COLUMN name text NOT NULL DEFAULT '';
