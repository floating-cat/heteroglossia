package np_carrier

import (
	"bytes"
	"io"
	"testing"

	"github.com/shoenig/test/must"
)

func TestPaddingCodecRoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte("a"), 1),
		bytes.Repeat([]byte("b"), maxOriginalPayloadSize+10), // spans multiple frames
		bytes.Repeat([]byte("c"), 100),
		[]byte("d"),
		[]byte("ee"),
		[]byte("fff"),
		bytes.Repeat([]byte("gggg"), 1000), // written after the padding is disabled
		[]byte("final raw bytes"),
	}

	var buf bytes.Buffer
	pw := &paddingWriter{w: &buf}
	var expected bytes.Buffer
	for _, payload := range payloads {
		n, err := pw.Write(payload)
		must.NoError(t, err)
		must.Eq(t, len(payload), n)
		expected.Write(payload)
	}

	pr := &paddingReader{r: &buf}
	actual, err := io.ReadAll(pr)
	must.NoError(t, err)
	must.Eq(t, expected.Bytes(), actual)
}
