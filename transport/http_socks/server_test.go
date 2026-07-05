package http_socks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport/direct"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/floating-cat/heteroglossia/util/strutil"
	"github.com/shoenig/test/must"
)

const (
	webServerAddr   = "http://127.0.0.1"
	proxyServerHost = "127.0.0.1"
)

var (
	correctAuthInfo = &conf.HTTPSOCKSAuthInfo{Username: "username", Password: "password"}
	wrongAuthInfo   = &conf.HTTPSOCKSAuthInfo{Username: "username", Password: "password1"}
)

func TestProxyConnectionHandle(t *testing.T) {
	webServerPort := startWebServer(t)
	webServerAddrWithPort := webServerAddr + ":" + strutil.ToA(webServerPort)
	proxyProtocolInfo := []struct {
		proxyProtocolName   string
		proxyProtocolPrefix string
	}{
		{"HTTP proxy", "http://"},
		{"SOCK5 proxy", "socks5h://"},
	}

	for _, i := range proxyProtocolInfo {
		prefix, webAddr := i.proxyProtocolPrefix, webServerAddrWithPort
		// serverAuth is what the proxy server requires; clientAuth is what the client sends
		t.Run(i.proxyProtocolName+" with a no-auth server",
			startServerAndClient(prefix, webAddr, nil, nil, false))
		t.Run(i.proxyProtocolName+" with an empty-auth server",
			startServerAndClient(prefix, webAddr, &conf.HTTPSOCKSAuthInfo{}, nil, false))
		t.Run(i.proxyProtocolName+" with matching authentication info",
			startServerAndClient(prefix, webAddr, correctAuthInfo, correctAuthInfo, false))
		t.Run(i.proxyProtocolName+" with incorrect authentication info",
			startServerAndClient(prefix, webAddr, correctAuthInfo, wrongAuthInfo, true))
	}
}

func startServerAndClient(proxyProtocolPrefix, webServerAddrWithPort string,
	serverAuth, clientAuth *conf.HTTPSOCKSAuthInfo, expectErr bool) func(t *testing.T) {
	return func(t *testing.T) {
		// run the client's assertions on the test goroutine: must.* calls FailNow,
		// which is only valid on the goroutine running the test
		clientErr := make(chan error, 1)
		serverErr := startProxyServer(t, serverAuth, func(ln net.Listener) {
			port := uint16(ln.Addr().(*net.TCPAddr).Port)
			go func() {
				proxyServerAddrWithPort := proxyProtocolPrefix + proxyServerHost + ":" + strutil.ToA(port)
				clientErr <- startClient(proxyServerAddrWithPort, webServerAddrWithPort, clientAuth)
			}()
		})
		assertErr(t, serverErr, expectErr)
		assertErr(t, <-clientErr, expectErr)
	}
}

func startProxyServer(t *testing.T, authInfo *conf.HTTPSOCKSAuthInfo, listenSuccessCallback func(ln net.Listener)) error {
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Second)
	defer cancel()
	done := make(chan error, 1)
	var err error
	go func() {
		select {
		case err = <-done:
			cancel()
		case <-ctx.Done():
			err = errors.New("timeout waiting for the proxy server to handle the connection", ctx.Err())
		}
	}()
	listenErr := netutil.ListenTCPAndServeWithListenerCallback(
		ctx,
		":0",
		func(tcpConn *net.TCPConn) {
			var httpSOCKS *conf.HTTPSOCKS
			if authInfo == nil {
				httpSOCKS = &conf.HTTPSOCKS{}
			} else {
				httpSOCKS = &conf.HTTPSOCKS{Username: authInfo.Username, Password: authInfo.Password}
			}
			err := (NewServer(httpSOCKS, direct.NewClient()).(*server)).Serve(t.Context(), tcpConn)
			done <- err
		},
		func(ln net.Listener) {
			listenSuccessCallback(ln)
		},
		nil)
	if listenErr != nil {
		return errors.New("failed to start proxy server", listenErr)
	}

	return err
}

func startClient(proxyServerAddrWithPort, webServerAddrWithPort string, authInfo *conf.HTTPSOCKSAuthInfo) error {
	var proxyUser string
	if authInfo.IsEmpty() {
		proxyUser = ""
	} else {
		proxyUser = fmt.Sprintf("-U %v:%v", authInfo.Username, authInfo.Password)
	}

	cmd := fmt.Sprintf("curl --fail --proxy %v %v %v",
		proxyServerAddrWithPort, proxyUser, webServerAddrWithPort)
	args := strings.Fields(cmd)
	_, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return err
}

func startWebServer(t *testing.T) uint16 {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	port := make(chan uint16, 1)

	go func() {
		err := netutil.ListenHTTPAndServeWithListenerCallback(t.Context(), ":0", mux, func(ln net.Listener) {
			port <- uint16(ln.Addr().(*net.TCPAddr).Port)
		})
		must.NoError(t, err)
	}()
	return <-port
}

func assertErr(t *testing.T, err error, expectErr bool) {
	t.Helper()
	if expectErr {
		must.Error(t, err)
	} else {
		must.NoError(t, err)
	}
}
