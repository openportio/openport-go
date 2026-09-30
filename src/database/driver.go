package database

import (
	"database/sql"

	sqlite "modernc.org/sqlite"
)

// modernc.org/sqlite registers itself as "sqlite", but gorm's built-in
// sqlite dialect (and every gorm.Open call in this package) expects the
// driver name "sqlite3", which mattn/go-sqlite3 used to claim. The file
// format is identical (modernc is a translation of the same SQLite
// sources), so existing openport.db files keep working — see the upgrade
// tests against testdata/openport-2.2.*.db.
func init() {
	sql.Register("sqlite3", &sqlite.Driver{})
}
