package database

import (
	"github.com/jinzhu/gorm"
	"path"
)
import log "github.com/sirupsen/logrus"
import "github.com/openportio/openport-go/utils"

var DEFAULT_OPENPORT_DB_PATH = path.Join(utils.OPENPORT_HOME, "openport.db")

type Session struct {
	// gorm.Model
	ID           int64  `gorm:"AUTO_INCREMENT;PRIMARY_KEY"`
	Server       string // The server to send the request to
	SessionToken string

	SshServer      string // The ssh server to connect to
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
	UseWS                 bool
	NoSSL                 bool
}

func (s Session) PrintMessage(message string) {
	if s.HttpForward {
		log.Infof("Now forwarding remote address %s to localhost", s.HttpForwardAddress)
	} else {
		log.Infof("Now forwarding remote port %s:%d to localhost:%d", s.SshServer, s.RemotePort, s.LocalPort)
	}
	log.Infof(message)
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
	db.First(&session, "local_port = ? and IFNULL(forward_tunnel, 0) = 0", localPort)
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

func (dbHandler *DBHandler) EnrichSessionWithHistory(session *Session) Session {
	if session.ForwardTunnel {
		if session.LocalPort < 0 {
			dbSession, err := dbHandler.GetForwardSession(session.RemotePort, session.SshServer)
			if err != nil {
				log.Errorf("error fetching session %s", err)
			} else {
				if dbSession.LocalPort > 0 && utils.PortIsAvailable(dbSession.LocalPort) {
					session.LocalPort = dbSession.LocalPort
					session.ID = dbSession.ID
				}
			}
			return dbSession
		}
	} else {
		dbSession, err := dbHandler.GetSession(session.LocalPort)
		if err != nil {
			log.Errorf("error fetching session %s", err)
		} else {
			if dbSession.RestartCommand != "" && session.RestartCommand == "" {
				log.Infof("Port forward for port %d that would be restarted on reboot will not be restarted anymore.", session.LocalPort)
			}

			if session.RemotePort < 0 || session.RemotePort == dbSession.RemotePort {
				session.SessionToken = dbSession.SessionToken
				session.RemotePort = dbSession.RemotePort
				session.ID = dbSession.ID
			}
		}
		return dbSession
	}
	return Session{}
}

func (dbHandler *DBHandler) DeleteSession(session Session) error {
	db, err := gorm.Open("sqlite3", dbHandler.DbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	db.Delete(&session)
	return db.Error
}
