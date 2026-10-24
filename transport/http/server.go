package http

import (
	"context"
	"io"
	"net"
	"net/http"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
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
// forked from https://github.com/database64128/shadowsocks-go/blob/88c2d63ccd0b022f76902195ceb1559eaf15a3a7/http/server.go
func (s *Server) Serve(ctx context.Context, conn net.Conn) error {
	ctx = contextutil.WithSourceAndInboundValues(ctx, conn.RemoteAddr().String(), "HTTP Proxy")
	buf := pool.Get(ioutil.BufSize)
	defer pool.Put(buf)
	connBufReader := ioutil.NewBufioReader(buf, conn)
	req, err := readRequest(connBufReader)
	if err != nil {
		return errors.WithStack(err)
	}

	isHTTPConnect := req.Method == http.MethodConnect
	var targetAddr *transport.SocketAddress
	if isHTTPConnect {
		// There is no default port; a client MUST send the port number
		// even if the CONNECT request is based on a URI reference that
		// contains an authority component with an elided port. For example
		// CONNECT server.example.com:80 HTTP/1.1
		// Host: server.example.com
		// A server MUST reject a CONNECT request that targets an empty
		// or invalid port number, typically by responding with a 400
		// (Bad Request) status code.
		// https://datatracker.ietf.org/doc/html/rfc9110#name-connect
		// A proxy that supports CONNECT establishes a TCP connection to the
		// host and port identified in the ":authority" pseudo-header field.
		// https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5
		targetAddr, err = transport.ToSocketAddr(req.URL.Host, true, 0)
	} else {
		targetAddr, err = transport.ToSocketAddr(req.Host, false, 80)
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
		unreadSize := connBufReader.Buffered()
		unreadBs, err := connBufReader.Peek(unreadSize)
		if err != nil {
			return errors.WithStack(err)
		}
		return transport.ForwardTCP(ctx, targetAddr, ioutil.NewBytesReadPreloadConn(unreadBs, conn), s.targetClient)
	}

	// relayConn reads data from the target server through forwardSrcConn
	// and sends it back to the client that made the request through the proxy.
	relayConn, forwardSrcConn := net.Pipe()
	go func() {
		buf := pool.Get(ioutil.BufSize)
		defer pool.Put(buf)
		relayConnBufReader := ioutil.NewBufioReader(buf, relayConn)
		var rerr, werr error
		var resp *http.Response
		for {
			removeHopByHopHeaders(req.Header)

			werr = req.Write(relayConn)
			if werr != nil {
				werr = errors.WithStack(werr)
				break
			}
			resp, rerr = http.ReadResponse(relayConnBufReader, req)
			if rerr != nil {
				rerr = errors.WithStack(rerr)
				break
			}
			rerr = resp.Write(conn)
			if rerr != nil {
				rerr = errors.WithStack(rerr)
				break
			}

			// https://datatracker.ietf.org/doc/html/rfc9110#name-connect
			// A tunnel is closed when a tunnel intermediary detects that
			// either side has closed its connection: the intermediary MUST
			// attempt to send any outstanding data that came from the closed
			// side to the other side, close both connections, and then
			// discard any remaining data left undelivered.
			if req.Close || resp.Close {
				break
			}
			req, werr = readRequest(connBufReader)
			if werr != nil {
				if errors.IsIoEof(werr) {
					werr = nil
				} else {
					werr = errors.WithStack(werr)
				}
				break
			}
		}

		_ = relayConn.Close()
		if rerr != nil {
			log.InfoWithError("fail to relay the response", rerr)
		}
		if werr != nil {
			log.InfoWithError("fail to relay the request", werr)
		}
	}()

	return transport.ForwardTCP(ctx, targetAddr, forwardSrcConn, s.targetClient)
}

func parse(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", "", false
	}
	return parseBasicAuth(auth)
}

func removeHopByHopHeaders(header http.Header) {
	connectionHeader := header["Connection"]
	for i := range connectionHeader {
		header.Del(connectionHeader[i])
	}
	delete(header, "Connection")
	delete(header, "Keep-Alive")
	delete(header, "Proxy-Authenticate")
	delete(header, "Proxy-Authorization")
	delete(header, "TE")
	delete(header, "Trailers")
	delete(header, "Transfer-Encoding")
	delete(header, "Upgrade")
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
