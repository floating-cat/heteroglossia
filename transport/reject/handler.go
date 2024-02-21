package reject

import (
	"io"

	"github.com/floating-cat/heteroglossia/transport"
)

type Handler struct{}

var _ transport.ConnectionContinuationHandler = new(Handler)

func (h *Handler) ForwardConnection(srcRWC io.ReadWriteCloser, _ *transport.SocketAddress) error {
	_ = srcRWC.Close()
	return nil
}
