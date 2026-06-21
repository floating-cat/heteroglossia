package main

import (
	"context"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/http_socks"
	"github.com/floating-cat/heteroglossia/transport/router"
	"github.com/floating-cat/heteroglossia/transport/tr_carrier"
	"github.com/floating-cat/heteroglossia/util/cli"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/floating-cat/heteroglossia/util/osutil"
	"github.com/floating-cat/heteroglossia/util/updater"
)

const DefaultDomainIPSetRulesDBFileName = "domain-ip-set-rules.db"

func main() {
	args := cli.Parse()
	var ruleDBFilePath = args.RulesDBFile
	if ruleDBFilePath == "" {
		ruleDBFilePath = filepath.Join(filepath.Dir(args.ConfigFile), DefaultDomainIPSetRulesDBFileName)
	}
	config, err := conf.Parse(args.ConfigFile, ruleDBFilePath)
	if err != nil {
		errors.PrintNoStack(err)
		return
	}

	log.SetVerbose(config.Misc.VerboseLog)
	if config.Misc.Profiling {
		go func() {
			err := netutil.ListenHTTPAndServe(context.Background(), ":"+strconv.Itoa(config.Misc.ProfilingPort), nil)
			if err != nil {
				log.Error("fail to start the profiling server", err)
			}
		}()
	}

	routeClient := router.NewClient(config.Route, config.Outbounds,
		ruleDBFilePath, config.Misc.RulesFileAutoUpdate, config.Misc.TLSKeyLog)
	if config.Inbounds.Hg != nil {
		go func() {
			server := tr_carrier.NewServer(config.Inbounds.Hg, routeClient)
			err := server.ListenAndServe(context.Background())
			if err != nil {
				log.Fatal("fail to start the hg server", err)
			}
		}()
	}
	if config.Inbounds.HTTPSOCKS != nil {
		go func() {
			server := http_socks.NewServer(config.Inbounds.HTTPSOCKS, routeClient)
			err := server.ListenAndServe(context.Background())
			if err != nil {
				log.Fatal("fail to start the HTTP/SOCKS server", err)
			}
		}()
	}

	if config.Misc.HgBinaryAutoUpdate {
		go updater.StartUpdateCron(func() {
			success, latestVersion, err := updater.UpdateHgBinary(transport.HTTPClientThroughRouter(routeClient))
			if err != nil {
				log.WarnWithError("fail to update the hg binary", err)
			}
			if !success {
				return
			}

			log.Info("update to the latest hg binary successfully", "version", latestVersion)
			selfRestart()
		})
	}

	select {}
}

func selfRestart() {
	log.Info("trying to start the new hg binary")
	executablePath, err := os.Executable()
	if err != nil {
		log.Error("fail to get the current hg binary executable path", err)
		return
	}
	// Windows does not support 'syscall.Exec'
	if runtime.GOOS == "windows" {
		cmd := exec.Command(executablePath, os.Args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		netutil.StopAllServerListeners()
		err = cmd.Run()
		if err != nil {
			log.InfoWithError("fail to start the new hg binary", errors.WithStack(err))
		}
		osutil.Exit(0)
	}
	err = syscall.Exec(executablePath, os.Args, os.Environ())
	if err != nil {
		log.Error("fail to start the new hg binary", err)
	}
}
