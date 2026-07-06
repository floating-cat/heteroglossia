package ioutil

import (
	"io"
	"os"
	"path/filepath"

	"github.com/floating-cat/heteroglossia/util/errors"
)

const BufSize = 4096

// ReadFile includes the file's abs path when an error occurs
func ReadFile(filePath string) ([]byte, error) {
	fullPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}
	return errors.WithStack2(os.ReadFile(fullPath))
}

func Read1(r io.Reader) (byte, error) {
	var bs [1]byte
	_, err := io.ReadFull(r, bs[:])
	return bs[0], errors.WithStack(err)
}

func ReadN(r io.Reader, n int) (int, []byte, error) {
	bs := make([]byte, n)
	count, err := io.ReadFull(r, bs)
	return count, bs, errors.WithStack(err)
}

// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#313-detection-prevention
// To process the salt and the fixed-length header, servers and clients MUST make exactly one read call

func ReadOnceExpectFull(r io.Reader, buf []byte) (int, error) {
	count, err := r.Read(buf)
	if err == nil && count < len(buf) {
		return count, errors.Newf("expect %v byte(s) in one read call, but got %v: %w",
			len(buf), count, io.ErrUnexpectedEOF)
	}
	return count, errors.WithStack(err)
}

func ReadFull(r io.Reader, buf []byte) (int, error) {
	return errors.WithStack2(io.ReadFull(r, buf))
}

func ReadByUint8(r io.Reader) ([]byte, error) {
	b, err := Read1(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	bs := make([]byte, b)
	_, err = io.ReadFull(r, bs)
	return bs, errors.WithStack(err)
}

func ReadStringByUint8(r io.Reader) (string, error) {
	bs, err := ReadByUint8(r)
	return string(bs), err
}

func Write(w io.Writer, response []byte) (int, error) {
	return errors.WithStack2(w.Write(response))
}

func Write_(w io.Writer, response []byte) error {
	_, err := Write(w, response)
	return err
}

func Pipe(a, b io.ReadWriteCloser) error {
	type closeWriter interface{ CloseWrite() error }
	done := make(chan error, 2)
	cp := func(dst, src io.ReadWriteCloser) {
		_, err := io.Copy(dst, src)
		cw, ok := dst.(closeWriter)
		if ok {
			_ = cw.CloseWrite()
		}
		done <- err
	}

	go cp(a, b)
	go cp(b, a)
	err1 := <-done
	err2 := <-done
	_ = a.Close()
	_ = b.Close()
	if errors.IsIoEof(err1) {
		err1 = nil
	}
	if errors.IsIoEof(err2) {
		err2 = nil
	}
	return errors.Append(err1, err2)
}
