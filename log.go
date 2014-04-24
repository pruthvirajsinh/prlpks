/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package prlpks

import (
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

// Logfile option
func (s *Settings) LogFile() string {
	return s.GetString("prlpks.logfile")
}

var logOut io.Writer = nil

// InitLog initializes the logging output to the globally configured settings.
// It also registers SIGHUP, SIGUSR1 and SIGUSR2 to close and reopen the log file
// for logrotate(8) support.
//
// BUG: If InitLog is called before the application is properly configured, it will automatically
// configure the application with an empty TOML (accept all defaults).
func InitLog() {
	if Config() == nil {
		SetConfig("")
	}
	if Config().LogFile() != "" {
		// Handle signals for log rotation
		sigChan := make(chan os.Signal)
		signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
		go func() {
			for {
				select {
				case _ = <-sigChan:
					closeable, canClose := logOut.(io.WriteCloser)
					openLog()
					if canClose {
						closeable.Close()
					}
					log.Println("Reopened logfile")
				}
			}
		}()
	}
	// Open the log
	openLog()
}

func openLog() {
	if Config().LogFile() != "" {
		var err error
		logOut, err = os.OpenFile(Config().LogFile(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Println("Failed to open logfile", err)
			logOut = os.Stderr
		} else {
			log.SetOutput(logOut)
		}
	} else {
		log.SetOutput(os.Stderr)
	}
	log.SetPrefix(filepath.Base(os.Args[0]))
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
