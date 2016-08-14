DROP TABLE IF EXISTS admins;
CREATE TABLE admins (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL
);

DROP TABLE IF EXISTS plugins;
CREATE TABLE plugins (
  id TEXT PRIMARY KEY,
  uploaded DATETIME DEFAULT CURRENT_TIMESTAMP,
  name TEXT NOT NULL,
  path TEXT NOT NULL,
  major_version TEXT NOT NULL,
  minor_version TEXT NOT NULL,
  maintenance_version TEXT NOT NULL,
  build_version TEXT NOT NULL
);