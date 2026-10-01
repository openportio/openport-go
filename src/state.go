package openport

import (
	"time"

	log "github.com/sirupsen/logrus"
)

type ConnectionState interface {
	DoState()
	IsConnected() bool
}

type ConnectedState struct {
	app *App
}

func (state *ConnectedState) DoState() {
	for {
		connected := <-state.app.Connected
		log.Debugf("Connected state: got Connected:  %t", connected)
		state.app.Session.Connected = connected
		state.app.SaveState()
		if connected {
			continue
		} else {
			state.app.ConnectedState = &DisconnectedState{
				app: state.app,
			}
			go state.app.ConnectedState.DoState()
			break
		}
	}
}

func (state *ConnectedState) IsConnected() bool {
	return true
}

type DisconnectedState struct {
	app *App
}

func (state *DisconnectedState) DoState() {

	var timeoutChannel <-chan time.Time
	if state.app.ExitOnFailureTimeout > 0 {
		timeoutChannel = time.After(time.Duration(state.app.ExitOnFailureTimeout) * time.Second)
	} else {
		// Hangs forever
		timeoutChannel = make(chan time.Time, 1)
	}

	select {
	case <-timeoutChannel:
		log.Errorf("Not Connected for %d seconds, exiting.", state.app.ExitOnFailureTimeout)
		state.app.Stop(EXIT_CODE_NO_CONNECTION)
	case connected := <-state.app.Connected:
		log.Debugf("disconnected state: got Connected:  %t", connected)
		state.app.Session.Connected = connected
		state.app.SaveState()
		if connected {
			state.app.ConnectedState = &ConnectedState{
				app: state.app,
			}
		} else {
			log.Debugf("Still disconnected after a failed reconnect.")
			state.app.ConnectedState = &DisconnectedState{
				app: state.app,
			}
		}
		go state.app.ConnectedState.DoState()
	}
}

func (state *DisconnectedState) IsConnected() bool {
	return false
}

func (app *App) MarkDisconnected() {
	// The connected event of a reconnect that died right away may still be
	// queued: drop it, or the state machine consumes it after this
	// disconnect, flips back to connected with nothing left to correct it,
	// and --exit-on-failure-timeout never fires.
	select {
	case <-app.Connected:
	default:
	}
	app.Connected <- false
}

func (app *App) MarkConnected() {
	app.Connected <- true
}
