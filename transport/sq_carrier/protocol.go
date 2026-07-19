package sq_carrier

import (
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// https://github.com/spongebob888/sunnyquic/blob/main/PROTOCOL.pdf
	tcpConnectCommand byte = 0 // TCP Connect, followed by a SOCKSADDR
	authCommand       byte = 5 // SunnyQUIC authentication, followed by AUTH_HASH

	// use 0 and an empty string for active detection
	connCloseErrCode                            = quic.ApplicationErrorCode(0)
	connCloseErrDesc                            = ""
	streamConnCloseErrCode quic.StreamErrorCode = 0

	// authTimeout bounds how long a proxy request waits for its connection to be
	// authenticated before being rejected.
	authTimeout = 5 * time.Second
)
