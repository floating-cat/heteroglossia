package errors

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mdobak/go-xerrors"
)

// examples:
// New("access denied")
// New("access denied", ErrReadError)

var New = xerrors.New

// examples:
// Newf("access denied: %v", "404")
// Newf("access denied: %v: %.0w", "404", ErrReadError)

var Newf = xerrors.Newf

var WithStack = xerrors.New

func WithStack2[T any](t T, err error) (T, error) {
	return t, xerrors.New(err)
}

var Append = xerrors.Append

var Is = errors.Is

func IsIoEof(err error) bool {
	return errors.Is(err, io.EOF)
}

func Print(w io.Writer, err error) {
	_, _ = xerrors.Fprint(w, err)
}

// PrintWithoutStacktrace forked from xerrors.Print
func PrintWithoutStacktrace(err error) {
	buf := &strings.Builder{}
	first := true
	for err != nil {
		_, ok := errors.AsType[xerrors.DetailedError](err)
		if ok {
			if first {
				buf.WriteString("Error: ")
			}
			buf.WriteString(err.Error())
		}
		first = false
		err = errors.Unwrap(err)
	}

	if buf.Len() != 0 {
		fmt.Println(buf.String())
	}
}
