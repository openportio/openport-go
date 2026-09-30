package database

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures in testdata/ were created by the released 2.2.0 and 2.2.3
// clients (mattn/go-sqlite3, cgo): each schema is what that binary's
// AutoMigrate produced, so they are missing the columns added since (2.2.0
// also lacks "connected"), and one row has a NULL restart_command. Opening
// them here proves that the pure-Go driver reads databases written by the
// C driver and that InitDB upgrades old schemas in place — the path every
// existing user's ~/.openport/openport.db takes on upgrade.
//
// Each fixture contains the same five sessions:
//   id 1: active, restart command, local port 22
//   id 2: active, http forward, local port 8080
//   id 3: inactive, local port 3306
//   id 4: active forward tunnel, restart command, remote port 41234
//   id 5: active, sparse row — most columns NULL, incl. restart_command
var fixtures = []string{"openport-2.2.0.db", "openport-2.2.3.db"}

func openFixture(t *testing.T, name string) *DBHandler {
	t.Helper()
	content, err := os.ReadFile(path.Join("testdata", name))
	require.NoError(t, err)
	dbPath := path.Join(t.TempDir(), "openport.db")
	require.NoError(t, os.WriteFile(dbPath, content, 0o600))
	return &DBHandler{DbPath: dbPath}
}

func TestUpgradeFromOldClient(t *testing.T) {
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			handler := openFixture(t, fixture)
			handler.InitDB() // panics if AutoMigrate cannot upgrade the schema

			active, err := handler.GetAllActive()
			require.NoError(t, err)
			assert.Len(t, active, 4)

			restart, err := handler.GetSessionsToRestart()
			require.NoError(t, err)
			require.Len(t, restart, 2, "NULL restart_command rows must not break the query")

			session, err := handler.GetSession(22)
			require.NoError(t, err)
			assert.Equal(t, "tok-restart", session.SessionToken)
			assert.Equal(t, 41234, session.RemotePort)
			assert.True(t, session.Active)
			// Columns added after 2.2.3 are NULL for pre-existing rows and
			// must scan as zero values.
			assert.False(t, session.TlsPassthrough)
			assert.Equal(t, "", session.HostKey)

			forward, err := handler.GetForwardSession(41234, "spr.openport.io")
			require.NoError(t, err)
			assert.Equal(t, "tok-forward", forward.SessionToken)
			assert.Equal(t, 22001, forward.LocalPort)

			// The sparse row: nearly every column NULL.
			sparse, err := handler.GetSession(9000)
			require.NoError(t, err)
			assert.Equal(t, "", sparse.RestartCommand)
			assert.True(t, sparse.Active)
		})
	}
}

func TestUpgradedRowsAreWritable(t *testing.T) {
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			handler := openFixture(t, fixture)
			handler.InitDB()

			session, err := handler.GetSession(22)
			require.NoError(t, err)

			// Update an old row through a column that did not exist when the
			// fixture was written.
			session.HostKey = "ssh-ed25519 AAAAtest"
			session.TlsPassthrough = true
			require.NoError(t, handler.Save(&session))

			reread, err := handler.GetSession(22)
			require.NoError(t, err)
			assert.Equal(t, "ssh-ed25519 AAAAtest", reread.HostKey)
			assert.True(t, reread.TlsPassthrough)
			assert.Equal(t, "tok-restart", reread.SessionToken, "existing columns must survive the update")

			handler.SetInactive(&session)
			active, err := handler.GetAllActive()
			require.NoError(t, err)
			assert.Len(t, active, 3)
		})
	}
}

func TestFreshDatabaseRoundtrip(t *testing.T) {
	handler := &DBHandler{DbPath: path.Join(t.TempDir(), "openport.db")}
	handler.InitDB()

	session := Session{
		Server:         "https://openport.io",
		SessionToken:   "tok-new",
		SshServer:      "spr.openport.io",
		RemotePort:     41300,
		LocalPort:      8443,
		Pid:            4321,
		Active:         true,
		RestartCommand: "openport 8443 --restart-on-reboot",
		TlsPassthrough: true,
		CustomDomain:   "example.com",
		TlsCertPath:    "/etc/openport/cert.pem",
		TlsKeyPath:     "/etc/openport/key.pem",
		LocalTLS:       true,
		HostKey:        "ssh-ed25519 AAAAexample",
		UseWS:          true,
	}
	require.NoError(t, handler.Save(&session))

	reread, err := handler.GetSession(8443)
	require.NoError(t, err)
	assert.Equal(t, "tok-new", reread.SessionToken)
	assert.Equal(t, "example.com", reread.CustomDomain)
	assert.True(t, reread.TlsPassthrough)
	assert.True(t, reread.LocalTLS)
	assert.True(t, reread.UseWS)

	require.NoError(t, handler.DeleteSession(reread))
	active, err := handler.GetAllActive()
	require.NoError(t, err)
	assert.Empty(t, active)
}

// Session processes and "openport restart-sessions" open the same database
// file from separate connections; the driver swap must not change that.
func TestTwoHandlesOnOneFile(t *testing.T) {
	dbPath := path.Join(t.TempDir(), "openport.db")
	first := &DBHandler{DbPath: dbPath}
	first.InitDB()
	second := &DBHandler{DbPath: dbPath}

	session := Session{LocalPort: 2222, RemotePort: 41400, Active: true, SessionToken: "tok-a"}
	require.NoError(t, first.Save(&session))

	seen, err := second.GetSession(2222)
	require.NoError(t, err)
	assert.Equal(t, "tok-a", seen.SessionToken)

	seen.Active = false
	require.NoError(t, second.Save(&seen))

	active, err := first.GetAllActive()
	require.NoError(t, err)
	assert.Empty(t, active)
}
