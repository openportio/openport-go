package main

import (
	o "github.com/openportio/openport-go"
	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/judwhite/go-svc"
)

// program implements svc.Service
type program struct {
	wg   sync.WaitGroup
	quit chan struct{}
}

func main() {
	prg := &program{}
	//o.InitLogging(true, "C:\\Users\\vagrant\\openport.log")
	o.InitLogging(true, o.LogPath)

	// Call svc.Run to start your program/service.
	if err := svc.Run(prg); err != nil {
		log.Fatal(err)
	}
}

func (p *program) Init(env svc.Environment) error {
	log.Printf("is win service? %v\n", env.IsWindowsService())
	return nil
}

func (p *program) Start() error {
	// The Start method must not block, or Windows may assume your service failed
	// to start. Launch a Goroutine here to do something interesting/blocking.

	p.quit = make(chan struct{})

	p.wg.Add(1)
	go func() {
		log.Println("Starting...")
		<-p.quit
		log.Println("Quit signal received...")
		p.wg.Done()
	}()

	go func() {
		app := o.CreateApp()
		app.DbHandler.DbPath = db.DEFAULT_OPENPORT_DB_PATH
		appPath := filepath.Join(filepath.Dir(os.Args[0]), "openportw.exe")

		log.Println("Restarting sessions...")
		log.Println("DB path: ", db.DEFAULT_OPENPORT_DB_PATH)
		log.Println("Home dir: ", utils.HOMEDIR)
		utils.EnsureHomeFolderExists()
		app.RestartSessions(appPath, o.DEFAULT_SERVER)
		p.quit <- struct{}{}
		os.Exit(<-app.ExitCode)
	}()

	return nil
}

func (p *program) Stop() error {
	// The Stop method is invoked by stopping the Windows service, or by pressing Ctrl+C on the console.
	// This method may block, but it's a good idea to finish quickly or your process may be killed by
	// Windows during a shutdown/reboot. As a general rule you shouldn't rely on graceful shutdown.

	log.Println("Stopping...")
	close(p.quit)
	p.wg.Wait()
	log.Println("Stopped.")
	return nil
}
