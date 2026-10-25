package np_carrier

import (
	"encoding/binary"
	"io"
	"math/rand/v2"

	"github.com/floating-cat/heteroglossia/util/errors"
	pool "github.com/libp2p/go-buffer-pool"
)

// NaïveProxy proxies bidirectional streams through HTTP/2 (or HTTP/3) CONNECT
// tunnels. The bidirectional streams operate in a sequence of reads and writes
// of data. The first kFirstPaddings (8) reads and writes in a bidirectional
// stream after the stream is established are padded in this format:
//
// struct PaddedData {
//  uint8_t original_data_size_high;  // original_data_size / 256
//  uint8_t original_data_size_low;  // original_data_size % 256
//  uint8_t padding_size;
//  uint8_t original_data[original_data_size];
//  uint8_t zeros[padding_size];
// };
// https://github.com/klzgrad/naiveproxy#proxy-payload-padding

type paddingReader struct {
	r                io.Reader
	count            int
	payloadRemaining int
	paddingRemaining int
}

func (pr *paddingReader) Read(p []byte) (n int, err error) {
	if pr.count >= firstPaddings {
		return pr.r.Read(p)
	}
	if len(p) == 0 {
		return 0, nil
	}

	for pr.payloadRemaining == 0 {
		var header [3]byte
		_, err := io.ReadFull(pr.r, header[:])
		if err != nil {
			if err == io.EOF {
				return 0, io.EOF
			}
			return 0, errors.WithStack(err)
		}
		pr.payloadRemaining = int(binary.BigEndian.Uint16(header[:2]))
		pr.paddingRemaining = int(header[2])
		// paddingWriter never sends a frame with an empty payload and only
		// padding, and neither does upstream NaiveProxy as far as we know, but
		// handling it keeps the reader robust against peers that do.
		if pr.payloadRemaining == 0 {
			err := pr.discardPadding()
			if err != nil {
				return 0, err
			}
			if pr.count >= firstPaddings {
				return pr.r.Read(p)
			}
		}
	}

	n, err = pr.r.Read(p[:min(len(p), pr.payloadRemaining)])
	pr.payloadRemaining -= n
	if err == io.EOF {
		if pr.payloadRemaining > 0 || pr.paddingRemaining > 0 {
			return n, errors.WithStack(io.ErrUnexpectedEOF)
		}
		return n, io.EOF
	}
	if err != nil {
		return n, errors.WithStack(err)
	}

	if pr.payloadRemaining == 0 {
		err = pr.discardPadding()
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (pr *paddingReader) discardPadding() error {
	if pr.paddingRemaining > 0 {
		n, err := io.CopyN(io.Discard, pr.r, int64(pr.paddingRemaining))
		pr.paddingRemaining -= int(n)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return errors.WithStack(err)
		}
	}
	pr.count++
	return nil
}

type paddingWriter struct {
	w     io.Writer
	count int
}

func (pw *paddingWriter) Write(p []byte) (int, error) {
	if pw.count >= firstPaddings {
		return pw.w.Write(p)
	}

	n := 0
	for len(p) > 0 && pw.count < firstPaddings {
		payloadChunk := p
		if len(payloadChunk) > maxOriginalPayloadSize {
			payloadChunk = payloadChunk[:maxOriginalPayloadSize]
		}
		paddingSize := rand.N(maxPaddingSize + 1)
		paddingPayloadBs := pool.Get(3 + len(payloadChunk) + paddingSize)
		binary.BigEndian.PutUint16(paddingPayloadBs[:2], uint16(len(payloadChunk)))
		paddingPayloadBs[2] = byte(paddingSize)
		copy(paddingPayloadBs[3:], payloadChunk)
		clear(paddingPayloadBs[3+len(payloadChunk):])

		_, err := pw.w.Write(paddingPayloadBs)
		pool.Put(paddingPayloadBs)
		if err != nil {
			return n, errors.WithStack(err)
		}
		n += len(payloadChunk)
		pw.count++
		p = p[len(payloadChunk):]
	}
	if len(p) > 0 {
		count, err := pw.w.Write(p)
		return n + count, errors.WithStack(err)
	}
	return n, nil
}
