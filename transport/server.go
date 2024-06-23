package transport

import (
	"context"
	"io"

	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
)

type Server interface {
	ListenAndServe(ctx context.Context) error
}

func ForwardTCP(ctx context.Context, accessAddr *SocketAddress, srcRwc io.ReadWriteCloser, targetClient Client) error {
	select {
	case <-ctx.Done():
		return errors.WithStack(ctx.Err())
	default:
		targetConn, err := targetClient.DialTCP(ctx, accessAddr)
		if err != nil {
			_ = srcRwc.Close()
			return err
		}
		return ioutil.Pipe(srcRwc, targetConn)
	}
}
