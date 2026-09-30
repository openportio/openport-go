package database

import (
	"context"
	"database/sql"
	"database/sql/driver"

	sqlite "modernc.org/sqlite"
)

// modernc.org/sqlite registers itself as "sqlite", but gorm's built-in
// sqlite dialect (and every gorm.Open call in this package) expects the
// driver name "sqlite3", which mattn/go-sqlite3 used to claim. The file
// format is identical (modernc is a translation of the same SQLite
// sources), so existing openport.db files keep working — see the upgrade
// tests against testdata/openport-2.2.*.db.
func init() {
	sql.Register("sqlite3", busyWaitDriver{inner: &sqlite.Driver{}})
}

// Several openport processes (sessions, restart-sessions, the app doing
// InitDB) open the same database file concurrently. Where mattn waited on
// a locked database, modernc fails straight away with SQLITE_BUSY, so give
// every connection a busy timeout instead of surfacing "database is
// locked" to the user.
type busyWaitDriver struct {
	inner driver.Driver
}

func (d busyWaitDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	execer, ok := conn.(driver.ExecerContext)
	if !ok {
		conn.Close()
		return nil, driver.ErrSkip
	}
	if _, err := execer.ExecContext(context.Background(), "PRAGMA busy_timeout(10000)", nil); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
