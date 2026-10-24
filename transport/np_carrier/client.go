package np_carrier

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/netutil"
)

type client struct {
	serverHostWithPort string
	basicAuthToken     string
	tlsConfig          *tls.Config
	transport          *http.Transport

	// NaiveProxy multiplexes every CONNECT tunnel over a single HTTP/2
	// connection, so clientConn is built once and reused until it can no
	// longer take new requests.
	clientConn      *clientConn
	clientConnMutex sync.Mutex
}

var _ transport.Client = (*client)(nil)

type clientConn struct {
	clientConn *http.ClientConn
	localAddr  net.Addr
	remoteAddr net.Addr
	// padding reports whether the latest CONNECT response from the server
	// supports padding
	padding atomic.Bool
}

// dialedConnKey is the context key under which getConn hands its already
// dialed TLS connection to the transport's DialTLSContext.
type dialedConnKey struct{}

func NewClient(proxyNode *conf.ProxyNode, tlsKeyLog bool) (transport.Client, error) {
	tlsConfig, err := netutil.TLSClientConfig(proxyNode.Host, proxyNode.TLSCustomCertFile, tlsKeyLog, false)
	if err != nil {
		return nil, err
	}

	tr := netutil.NewHTTPTransport()
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	tr.Protocols = protocols
	tr.DialTLSContext = func(ctx context.Context, network string, addr string) (net.Conn, error) {
		tlsConn, ok := ctx.Value(dialedConnKey{}).(*tls.Conn)
		if !ok {
			return nil, errors.New("no dialed connection to the server")
		}
		return tlsConn, nil
	}
	return &client{
		serverHostWithPort: netutil.JoinHostPort(proxyNode.Host, proxyNode.TLSPort),
		basicAuthToken:     basicAuthPrefix + basicAuthToken(proxyNode.Password[:]),
		tlsConfig:          tlsConfig,
		transport:          tr,
	}, nil
}

func (c *client) DialTCP(ctx context.Context, addr *transport.SocketAddress) (net.Conn, error) {
	clientConn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}

	host := addr.ToHostStr()
	pipeReader, pipeWriter := io.Pipe()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: host},
		Host:   host,
		Header: make(http.Header),
		Body:   pipeReader,
	}
	req = req.WithContext(ctx)
	req.Header.Set(proxyAuthHeaderKey, c.basicAuthToken)
	req.Header.Set(paddingHeaderKey, generatePaddingHeader(true))

	// The first CONNECT request to a server cannot use "Fast Open" to send
	// payload before response, because the server's padding capability has not
	// been determined from the first response, and it's unknown whether to
	// send padded or unpadded payload for "Fast Open".
	// https://github.com/klzgrad/naiveproxy#opt-in-of-padding-protocol
	// Enables "Fast Open" when the server supports padding and disables it
	// when the server's padding support is unknown or the server does not
	// support padding.
	if clientConn.padding.Load() {
		return clientConn.fastOpen(req, host, pipeWriter), nil
	}

	respBody, padding, err := clientConn.connect(req, host)
	if err != nil {
		_ = pipeWriter.Close()
		return nil, err
	}
	closeFunc := func() error {
		err := respBody.Close()
		_ = pipeWriter.Close()
		return err
	}
	return newConn(respBody, pipeWriter, padding,
		closeFunc, pipeWriter.Close, clientConn.localAddr, clientConn.remoteAddr), nil
}

// fastOpen returns a conn right away without waiting for the CONNECT response,
// so the payload follows the request instead of a round trip later.
func (conn *clientConn) fastOpen(req *http.Request, host string, pipeWriter *io.PipeWriter) net.Conn {
	// Cancel the request if the client is closed before the response arrives.
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	body := &pendingBody{done: make(chan struct{})}
	go func() {
		defer close(body.done)
		respBody, _, err := conn.connect(req, host)
		body.rc, body.err = respBody, err
	}()

	closeFunc := func() error {
		cancel()
		return pipeWriter.Close()
	}
	return newConn(body, pipeWriter, true, closeFunc, pipeWriter.Close, conn.localAddr, conn.remoteAddr)
}

// connect sends the CONNECT request and waits for its response.
func (conn *clientConn) connect(req *http.Request, host string) (io.ReadCloser, bool, error) {
	resp, err := conn.clientConn.RoundTrip(req)
	if err != nil {
		return nil, false, errors.Newf("CONNECT request to %v failed: %.0w", host, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, false, errors.Newf("server returned unexpected status %v for %v", resp.StatusCode, host)
	}

	// NaiveProxy servers and clients determines whether the counterpart is
	// capable of this padding protocol by the presence of the padding header
	// in the CONNECT request and response respectively. The padding protocol
	// is enabled only if the padding header exists.
	// https://github.com/klzgrad/naiveproxy#opt-in-of-padding-protocol
	padding := resp.Header.Get(paddingHeaderKey) != ""
	conn.padding.Store(padding)
	return resp.Body, padding, nil
}

// getConn returns a live HTTP/2 connection to the NaiveProxy server, dialing a
// new one when none is cached or the cached one can no longer take requests.
// It reserves a request slot on the connection, which the caller must use up
// with RoundTrip or give back with Release.
func (c *client) getConn(ctx context.Context) (*clientConn, error) {
	c.clientConnMutex.Lock()
	defer c.clientConnMutex.Unlock()
	// Reserve a slot rather than only checking Available(), so no other caller
	// can take it before this caller's RoundTrip starts.
	if c.clientConn != nil && c.clientConn.clientConn.Reserve() == nil {
		return c.clientConn, nil
	}
	c.clientConn = nil

	tlsConn, err := netutil.DialTLS(ctx, c.serverHostWithPort, c.tlsConfig)
	if err != nil {
		return nil, errors.Newf("fail to connect to the server %v: %.0w", c.serverHostWithPort, err)
	}
	err = netutil.HandshakeTLS(ctx, tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, errors.Newf("fail to complete the TLS handshake with the server %v: %.0w", c.serverHostWithPort, err)
	}
	// The transport falls back to HTTP/1.1 when "h2" isn't negotiated, which
	// NaiveProxy doesn't speak.
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = tlsConn.Close()
		return nil, errors.Newf("server %v didn't negotiate HTTP/2", c.serverHostWithPort)
	}

	dialedCtx := context.WithValue(ctx, dialedConnKey{}, tlsConn)
	conn, err := c.transport.NewClientConn(dialedCtx, "https", c.serverHostWithPort)
	if err != nil {
		_ = tlsConn.Close()
		return nil, errors.WithStack(err)
	}
	err = conn.Reserve()
	if err != nil {
		_ = conn.Close()
		return nil, errors.WithStack(err)
	}

	c.clientConn = &clientConn{
		clientConn: conn,
		localAddr:  tlsConn.LocalAddr(),
		remoteAddr: tlsConn.RemoteAddr(),
	}
	return c.clientConn, nil
}

// pendingBody is the body of a CONNECT response that may not have arrived yet.
type pendingBody struct {
	done chan struct{}
	rc   io.ReadCloser
	err  error
}

func (pb *pendingBody) Read(p []byte) (n int, err error) {
	<-pb.done
	if pb.err != nil {
		return 0, pb.err
	}
	return pb.rc.Read(p)
}
