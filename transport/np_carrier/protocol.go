package np_carrier

const (
	// maxPaddingSize is a random integer uniformly distributed in
	// [0, kMaxPaddingSize] (kMaxPaddingSize: 255).
	// maxOriginalPayloadSize cannot be greater than 65535, or it has to be
	// split into several reads or writes.
	// firstPaddings is chosen to be 8 to flatten the packet length
	// distribution spikes formed from common initial handshakes
	// https://github.com/klzgrad/naiveproxy/tree/0539676ac91d9607caa00869b709e66643b91ac5#h2-headers-frame-padding
	maxPaddingSize         = 255
	maxOriginalPayloadSize = 65535
	firstPaddings          = 8

	proxyAuthHeaderKey = "Proxy-Authorization"
	paddingHeaderKey   = "Padding"
	basicAuthPrefix    = "Basic "
)
