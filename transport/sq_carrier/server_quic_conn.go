package sq_carrier

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/socks"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
	pool "github.com/libp2p/go-buffer-pool"
	"github.com/quic-go/quic-go"
)

type serverQUICConn struct {
	*server
	quicConn *quic.Conn

	ctx      context.Context
	cancel   context.CancelFunc
	authDone chan struct{}
	authOnce sync.Once
}

func newServerQUICConn(ctx context.Context, server *server, quicConn *quic.Conn) *serverQUICConn {
	ctx, cancel := context.WithCancel(ctx)
	return &serverQUICConn{server: server, quicConn: quicConn, ctx: ctx, cancel: cancel, authDone: make(chan struct{})}
}

func (c *serverQUICConn) handleAuthTimeout() {
	select {
	case <-c.ctx.Done():
	case <-c.authDone:
	case <-time.After(authTimeout):
		_ = c.Close()
	}
}

func (c *serverQUICConn) handleUniStreams(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptUniStream(c.ctx)
		if err != nil {
			if !errors.IsNetErrClosedOrContextCanceled(err) {
				log.InfoWithError("fail to accept a QUIC unidirectional stream", errors.WithStack(err))
			}
			return
		}
		go func() {
			err = c.handleUniStream(stream)
			if err != nil {
				log.InfoWithError("fail to handle a QUIC unidirectional stream", err)
			}
		}()
	}
}

func (c *serverQUICConn) handleUniStream(stream *quic.ReceiveStream) error {
	command, err := ioutil.Read1(stream)
	if err != nil {
		return err
	}

	switch command {
	case authCommand:
		err := c.handleAuthCommand(stream)
		if err != nil {
			_ = c.Close()
		}
		return err
	default:
		return errors.Newf("unsupported command type %v", command)
	}
}

func (c *serverQUICConn) handleAuthCommand(stream *quic.ReceiveStream) error {
	authHashBs := pool.Get(len(c.authHash))
	defer pool.Put(authHashBs)
	_, err := ioutil.ReadFull(stream, authHashBs)
	if err != nil {
		return err
	}
	if !bytes.Equal(authHashBs, c.authHash[:]) {
		return errors.New("incorrect auth hash")
	}
	c.authOnce.Do(func() {
		close(c.authDone)
	})
	return nil
}

func (c *serverQUICConn) handleStreams(conn *quic.Conn) {
	select {
	case <-c.ctx.Done():
		return
	case <-c.authDone: // for server, it should block any commands until authentication is finished
	}

	for {
		stream, err := conn.AcceptStream(c.ctx)
		if err != nil {
			if !errors.IsNetErrClosedOrContextCanceled(err) {
				log.InfoWithError("fail to accept a QUIC stream", errors.WithStack(err))
			}
			return
		}
		go func() {
			err = c.handleStream(stream)
			_ = stream.Close()
			if err != nil {
				log.InfoWithError("fail to handle a QUIC stream", err)
			}
		}()
	}
}

func (c *serverQUICConn) handleStream(stream *quic.Stream) error {
	command, err := ioutil.Read1(stream)
	if err != nil {
		return err
	}

	switch command {
	case tcpConnectCommand:
		return c.handleTCPConnectCommand(stream)
	default:
		return errors.Newf("unsupported command type %v", command)
	}
}

func (c *serverQUICConn) handleTCPConnectCommand(stream *quic.Stream) error {
	accessAddr, err := socks.ReadSOCKS5Address(stream)
	if err != nil {
		return err
	}
	return transport.ForwardTCP(c.ctx, accessAddr, newStreamConn(stream, c.quicConn), c.targetClient)
}

func (c *serverQUICConn) Close() error {
	c.cancel()
	return c.quicConn.CloseWithError(connCloseErrCode, connCloseErrDesc)
}
