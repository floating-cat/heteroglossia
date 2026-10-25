package log

import (
	"log/slog"
	"os"
	"sync/atomic"

	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/osutil"
)

var (
	defaultWriter = os.Stderr
	verbose       = atomic.Bool{}
	logLevel      = new(slog.LevelVar)
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(defaultWriter, &slog.HandlerOptions{Level: logLevel})))
}

func SetVerbose(b bool) {
	verbose.Store(b)
	if b {
		logLevel.Set(slog.LevelDebug)
	} else {
		logLevel.Set(slog.LevelInfo)
	}
}

var Info = slog.Info

func InfoWithError(msg string, err error, args ...any) {
	if verbose.Load() == true {
		slog.Info(msg, args...)
		errors.Print(defaultWriter, err)
	} else {
		slog.Info(msg, append(args, "err", err)...)
	}
}

var Warn = slog.Warn

func WarnWithError(msg string, err error, args ...any) {
	slog.Warn(msg, args...)
	errors.Print(defaultWriter, err)
}

func Error(msg string, err error, args ...any) {
	slog.Error(msg, args...)
	errors.Print(defaultWriter, err)
}

func Fatal(msg string, err error, args ...any) {
	slog.Error(msg, args...)
	errors.Print(defaultWriter, err)
	osutil.Exit(1)
}
