package http

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	pool "github.com/libp2p/go-buffer-pool"
)

type Server struct {
	authInfo     *conf.HTTPSOCKSAuthInfo
	targetClient transport.Client
}

var _ transport.Server = (*Server)(nil)

func NewServer(authInfo *conf.HTTPSOCKSAuthInfo, targetClient transport.Client) *Server {
	return &Server{authInfo, targetClient}
}

// https://www.mnot.net/blog/2011/07/11/what_proxies_must_do
// point 0: always advise HTTP 1.1
// point 1: remove Hop-by-hop headers
// point 3: an absolute URI always override the Host header

var connectSuccessBytes = []byte("HTTP/1.1 200 OK\r\n\r\n")

func (s *Server) ListenAndServe(context.Context) error {
	panic("not implemented")
}

// Serve always consider connection persistent and take little care of HTTP
// connection header to make the impl simper.
func (s *Server) Serve(ctx context.Context, conn net.Conn) error {
	ctx = contextutil.WithSourceAndInboundValues(ctx, conn.RemoteAddr().String(), "HTTP Proxy")
	buf := pool.Get(ioutil.BufSize)
	defer pool.Put(buf)
	connBufReader := ioutil.NewBufioReader(buf, conn)
	req, err := http.ReadRequest(connBufReader)
	if err != nil {
		return errors.WithStack(err)
	}

	isHTTPConnect := req.Method == http.MethodConnect
	var targetAddr *transport.SocketAddress
	if isHTTPConnect {
		// CONNECT uses a special form of request target, unique to this
		// method, consisting of only the host and port number of the tunnel
		// destination, separated by a colon. There is no default port; a
		// client MUST send the port number even if the CONNECT request is
		// based on a URI reference that contains an authority component with
		// an elided port.
		// https://www.rfc-editor.org/info/rfc9110/#section-9.3.6
		targetAddr, err = transport.ToSocketAddr(req.URL.Host, true, 0)
	} else {
		// When making a request to a proxy, other than a CONNECT or
		// server-wide OPTIONS request, a client MUST send the target URI in
		// "absolute-form" as the request-target.
		// GET http://www.example.org/pub/WWW/TheProject.html HTTP/1.1
		// When a proxy receives a request with an absolute-form of
		// request-target, the proxy MUST ignore the received Host header field
		// (if any) and instead replace it with the host information of the
		// request-target.
		// https://www.rfc-editor.org/info/rfc9112/#name-absolute-form
		targetAddr, err = transport.ToSocketAddr(req.URL.Host, false, 80)
	}
	if err != nil {
		return errors.Append(err, httpError(conn, http.StatusBadRequest, nil))
	}
	if !s.authInfo.IsEmpty() {
		username, password, ok := parse(req)
		if !ok || s.authInfo.NotEqual2(username, password) {
			return errors.Append(errors.New("no authentication info, or incorrect username/password"),
				httpError(conn, http.StatusProxyAuthRequired, http.Header{"Proxy-Authenticate": {"Basic"}}))
		}
	}
	if isHTTPConnect {
		err = ioutil.Write_(conn, connectSuccessBytes)
		if err != nil {
			return err
		}
		unreadLen := connBufReader.Buffered()
		unreadBs, err := connBufReader.Peek(unreadLen)
		if err != nil {
			return errors.WithStack(err)
		}
		return transport.ForwardTCP(ctx, targetAddr, ioutil.NewBytesReadPreloadConn(unreadBs, conn), s.targetClient)
	}

	return s.relay(ctx, conn, connBufReader, req, targetAddr)
}

// relay sends req and the requests that follow it on clientConn to their
// hosts, and writes each response back to clientConn. A client may send
// requests for different hosts over one connection, so relay dials again
// whenever the host changes.
func (s *Server) relay(ctx context.Context, clientConn net.Conn, clientConnBufReader *bufio.Reader,
	req *http.Request, targetAddr *transport.SocketAddress) error {
	buf := pool.Get(ioutil.BufSize)
	defer pool.Put(buf)
	var targetConn net.Conn
	var targetBufReader *bufio.Reader
	var targetHost string
	defer func() {
		if targetConn != nil {
			_ = targetConn.Close()
		}
	}()

	for {
		host := targetAddr.ToHostStr()
		if targetConn == nil || host != targetHost {
			if targetConn != nil {
				_ = targetConn.Close()
				targetConn = nil
			}
			dialedConn, err := s.targetClient.DialTCP(ctx, targetAddr)
			if err != nil {
				return errors.Append(err, httpError(clientConn, http.StatusBadGateway, nil))
			}
			targetConn, targetHost = dialedConn, host
			targetBufReader = ioutil.NewBufioReader(buf, targetConn)
		}

		removeHopByHopHeaders(req.Header)
		err := req.Write(targetConn)
		if err != nil {
			return errors.WithStack(err)
		}
		resp, err := http.ReadResponse(targetBufReader, req)
		if err != nil {
			return errors.WithStack(err)
		}
		removeHopByHopHeaders(resp.Header)
		err = resp.Write(clientConn)
		if err != nil {
			return errors.WithStack(err)
		}
		if req.Close || resp.Close {
			return nil
		}

		req, err = http.ReadRequest(clientConnBufReader)
		if err != nil {
			if errors.IsIoEof(err) {
				return nil
			}
			return errors.WithStack(err)
		}
		targetAddr, err = transport.ToSocketAddr(req.URL.Host, false, 80)
		if err != nil {
			return errors.Append(err, httpError(clientConn, http.StatusBadRequest, nil))
		}
	}
}

func parse(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", "", false
	}
	return parseBasicAuth(auth)
}

func removeHopByHopHeaders(header http.Header) {
	// https://www.rfc-editor.org/info/rfc2616/#section-13.5.1
	for _, value := range header["Connection"] {
		for field := range strings.SplitSeq(value, ",") {
			field = strings.TrimSpace(field)
			if field != "" {
				header.Del(field)
			}
		}
	}
	header.Del("Connection")
	header.Del("Keep-Alive")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
	header.Del("TE")
	// Some older RFCs use "Trailers", which is a typo.
	header.Del("Trailer")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")
}

func httpError(w io.Writer, statusCode int, header http.Header) error {
	resp := http.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Close:      true,
	}
	return errors.WithStack(resp.Write(w))
}
