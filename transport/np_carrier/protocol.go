package np_carrier

const (
	// maxPaddingSize is a random integer uniformly distributed in
	// [0, kMaxPaddingSize] (kMaxPaddingSize: 255).
	// maxOriginalPayloadSize cannot be greater than 65535, or it has to be
	// split into several reads or writes.
	// firstPaddings is chosen to be 8 to flatten the packet length
	// distribution spikes formed from common initial handshakes
	// https://github.com/klzgrad/naiveproxy/#proxy-payload-padding
	maxPaddingSize         = 255
	maxOriginalPayloadSize = 65535
	firstPaddings          = 8

	proxyAuthHeaderKey = "Proxy-Authorization"
	paddingHeaderKey   = "Padding"
	basicAuthPrefix    = "Basic "
)
