package database

type DummyDBHandler struct {
}

func (dbHandler *DummyDBHandler) SetPath(dbPath string) {}

func (dbHandler *DummyDBHandler) Path() string {
	return "no path, this is a dummy"
}

func (dbHandler *DummyDBHandler) GetSessionsToRestart() ([]Session, error) {
	return []Session{}, nil
}

func (dbHandler *DummyDBHandler) EnrichSessionWithHistory(d *Session) Session {
	return *d
}

func (dbHandler *DummyDBHandler) DeleteSession(session Session) error {
	return nil
}

func (dbHandler *DummyDBHandler) GetAllActive() ([]Session, error) {
	return []Session{}, nil
}

func (dbHandler *DummyDBHandler) SetInactive(session *Session) {}

func (dbHandler *DummyDBHandler) InitDB() {}

func (dbHandler *DummyDBHandler) GetForwardSession(remotePort int, sshServer string) (Session, error) {
	return Session{}, nil
}

func (dbHandler *DummyDBHandler) GetSession(localPort int) (Session, error) {
	return Session{}, nil
}

func (dbHandler *DummyDBHandler) Save(session *Session) error {
	return nil
}
