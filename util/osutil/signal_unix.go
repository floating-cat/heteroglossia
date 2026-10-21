//go:build unix

package osutil

import (
	"os"
	"os/signal"
	"syscall"
	_ "unsafe"
)

func listenEndSignalAndRunHandler() {
	end := make(chan os.Signal, 1)
	signal.Notify(end,
		// https://sourceware.org/glibc/manual/latest/html_node/Termination-Signals.html
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGHUP,
	)

	sig := <-end
	signal.Stop(end)
	runHandlers()
	err := syscall.Kill(syscall.Getpid(), sig.(syscall.Signal))
	if err != nil {
		panic(err)
	}
}

//go:linkname runHandlers github.com/tebeka/atexit.runHandlers
func runHandlers()
