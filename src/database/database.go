package database

import "github.com/jinzhu/gorm"
import log "github.com/sirupsen/logrus"
import "github.com/openportio/openport-go/utils"

var OPENPORT_DB_PATH = utils.OPENPORT_HOME + "/openport.db"

type Session struct {
	// gorm.Model
	ID           int64 `gorm:"AUTO_INCREMENT;PRIMARY_KEY"`
	Server       string
	SessionToken string

	SshServer      string
	RemotePort     int
	LocalPort      int
	Pid            int
	Active         bool   // Means that the session should be running
	RestartCommand string // If empty, do not restart

	AccountId          int
	KeyId              int
	HttpForward        bool
	HttpForwardAddress string

	AppManagementPort   int
	OpenPortForIpLink   string
	UseIpLinkProtection string

	KeepAliveSeconds int
	Proxy            string
	ForwardTunnel    bool `sql:"default:false"`

	FallbackSshServerIp   string `gorm:"-"`
	FallbackSshServerPort int    `gorm:"-"`
	AutomaticRestart      bool   `gorm:"-"`
}

type DBHandler struct {
	DbPath string
}

func (dbHandler *DBHandler) InitDB() {
	log.Debugf("db path: %s", dbHandler.DbPath)
	db, err := gorm.Open("sqlite3", dbHandler.DbPath)
	if err != nil {
		log.Panicf("failed to connect database: %s", err)
	}
	defer db.Close()

	// Migrate the schema
	db.AutoMigrate(&Session{})
	log.Debugf("db created")
}

func (dbHandler *DBHandler) GetForwardSession(remotePort int, sshServer string) (Session, error) {
	db, err := gorm.Open("sqlite3", dbHandler.DbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var session Session
	var whereClause string
	if sshServer != "" {
		whereClause = "remote_port = ? and (ssh_server = ? or ifnull(ssh_server, '') = '') and forward_tunnel = 1"
	} else {
		whereClause = "remote_port = ? and forward_tunnel = 1"
	}
	db.First(&session, whereClause, remotePort, sshServer)
	if db.Error != nil {
		return session, db.Error
	}
	return session, nil
}

func (dbHandler *DBHandler) GetSession(localPort int) (Session, error) {
	db, err := gorm.Open("sqlite3", dbHandler.DbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var session Session
	db.First(&session, "local_port = ? and forward_tunnel = ?", localPort, false)
	if db.Error != nil {
		return session, db.Error
	}
	return session, nil
}

func (dbHandler *DBHandler) Save(session *Session) error {
	db, err := gorm.Open("sqlite3", dbHandler.DbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var existingSession Session
	if session.ForwardTunnel {
		existingSession, err = dbHandler.GetForwardSession(session.RemotePort, session.SshServer)
	} else {
		existingSession, err = dbHandler.GetSession(session.LocalPort)
	}
	if err == nil {
		session.ID = existingSession.ID
	} else {
		return err
	}
	db.Save(session)
	return db.Error
}

func (dbHandler *DBHandler) GetAllActive() ([]Session, error) {
	db, err := gorm.Open("sqlite3", dbHandler.DbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var sessions []Session
	db.Where("active = 1").Find(&sessions)
	return sessions, db.Error
}

func (dbHandler *DBHandler) GetSessionsToRestart() ([]Session, error) {
	db, err := gorm.Open("sqlite3", dbHandler.DbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var sessions []Session
	db.Where("ifnull(restart_command, '') != '' ").Find(&sessions)
	return sessions, db.Error
}
