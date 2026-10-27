package http

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport/direct"
	"github.com/floating-cat/heteroglossia/transport/reject"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/floating-cat/heteroglossia/util/testutil"
	"github.com/shoenig/test/must"
)

func TestHTTPServer(t *testing.T) {
	testutil.TestHTTPSOCKSServer(t, "http", newServeFunc)
}

// TestHTTPServerSendsEachRequestToItsHost checks that requests for different
// hosts on one connection each go to their own host.
func TestHTTPServerSendsEachRequestToItsHost(t *testing.T) {
	servers := map[string]*httptest.Server{}
	for _, name := range []string{"A", "B"} {
		servers[name] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, name)
		}))
		defer servers[name].Close()
	}

	proxyAddr := testutil.StartProxyServer(t, newServeFunc(&conf.HTTPSOCKSAuthInfo{}))
	conn, err := net.Dial("tcp", proxyAddr)
	must.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()
	must.NoError(t, conn.SetDeadline(time.Now().Add(testutil.Timeout)))

	connReader := bufio.NewReader(conn)
	for _, name := range []string{"A", "B", "A"} {
		req, err := http.NewRequest(http.MethodGet, servers[name].URL, nil)
		must.NoError(t, err)
		must.NoError(t, req.WriteProxy(conn))
		resp, err := http.ReadResponse(connReader, req)
		must.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		must.NoError(t, err)
		must.EqOp(t, name, string(body))
	}
}

// TestHTTPServerRelaysPipelinedRequests checks that requests a client sends
// without waiting for the earlier responses all get their responses.
func TestHTTPServerRelaysPipelinedRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	defer server.Close()

	proxyAddr := testutil.StartProxyServer(t, newServeFunc(&conf.HTTPSOCKSAuthInfo{}))
	conn, err := net.Dial("tcp", proxyAddr)
	must.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()
	must.NoError(t, conn.SetDeadline(time.Now().Add(testutil.Timeout)))

	paths := []string{"/a", "/b", "/c"}
	for _, path := range paths {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		must.NoError(t, err)
		must.NoError(t, req.WriteProxy(conn))
	}
	connReader := bufio.NewReader(conn)
	for _, path := range paths {
		resp, err := http.ReadResponse(connReader, nil)
		must.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		must.NoError(t, err)
		must.EqOp(t, path, string(body))
	}
}

// TestHTTPServerRepliesBadGatewayWhenDialFails checks that a client gets a
// response even when the target can't be reached.
func TestHTTPServerRepliesBadGatewayWhenDialFails(t *testing.T) {
	proxyAddr := testutil.StartProxyServer(t, NewServer(&conf.HTTPSOCKSAuthInfo{}, reject.Client).Serve)
	resp, err := newProxyClient(proxyAddr).Get("http://example.com/")
	must.NoError(t, err)
	_ = resp.Body.Close()
	must.EqOp(t, http.StatusBadGateway, resp.StatusCode)
}

// TestHTTPServerRelaysResponseEndedByClose checks that a client gets the end of
// a response whose length is only known when the target closes the connection.
func TestHTTPServerRelaysResponseEndedByClose(t *testing.T) {
	ln, err := net.Listen("tcp", netutil.IPv4LocalhostAnyPort)
	must.NoError(t, err)
	defer func() {
		_ = ln.Close()
	}()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()
		_, err = http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello")
	}()

	proxyAddr := testutil.StartProxyServer(t, newServeFunc(&conf.HTTPSOCKSAuthInfo{}))
	resp, err := newProxyClient(proxyAddr).Get("http://" + ln.Addr().String())
	must.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	must.NoError(t, err)
	must.EqOp(t, "hello", string(body))
}

// TestHTTPServerClosesTargetConnWhenClientCloses checks that the proxy closes
// the target connection when the client closes its connection while waiting
// for a response.
func TestHTTPServerClosesTargetConnWhenClientCloses(t *testing.T) {
	ln, err := net.Listen("tcp", netutil.IPv4LocalhostAnyPort)
	must.NoError(t, err)
	defer func() {
		_ = ln.Close()
	}()
	gotRequest := make(chan struct{})
	targetConnErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			targetConnErr <- err
			return
		}
		defer func() {
			_ = conn.Close()
		}()
		_ = conn.SetDeadline(time.Now().Add(testutil.Timeout))
		// Never respond, like a target holding a long poll.
		connReader := bufio.NewReader(conn)
		_, err = http.ReadRequest(connReader)
		if err != nil {
			targetConnErr <- err
			return
		}
		close(gotRequest)
		_, err = connReader.ReadByte()
		targetConnErr <- err
	}()

	proxyAddr := testutil.StartProxyServer(t, newServeFunc(&conf.HTTPSOCKSAuthInfo{}))
	conn, err := net.Dial("tcp", proxyAddr)
	must.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String(), nil)
	must.NoError(t, err)
	must.NoError(t, req.WriteProxy(conn))
	select {
	case <-gotRequest:
	case err := <-targetConnErr:
		t.Fatal(err)
	}
	must.NoError(t, conn.Close())
	must.ErrorIs(t, <-targetConnErr, io.EOF)
}

func newProxyClient(proxyAddr string) *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   testutil.Timeout,
	}
}

func newServeFunc(authInfo *conf.HTTPSOCKSAuthInfo) testutil.ServeFunc {
	return NewServer(authInfo, direct.Client).Serve
}
