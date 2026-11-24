package src

import "database/sql"

type OpenvpnUser struct {
	Database *sql.DB
	// SpoolDir is where a login that may not write the database leaves its re-hash (see rehash_spool.go); "" = none.
	SpoolDir string
}

type Migration struct {
	id   int64
	name string
	sql  string
}

type User struct {
	id            int64
	name          string
	password      string
	revoked       bool
	deleted       bool
	secret        string
	appConfigured bool
}
