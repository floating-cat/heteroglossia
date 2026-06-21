package errors

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mdobak/go-xerrors"
)

// New examples:
// New("access denied")
// New("access denied", ErrReadError)
var New = xerrors.New

// Newf examples:
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

// PrintNoStack forked from xerrors.Print
func PrintNoStack(err error) {
	buf := &strings.Builder{}
	first := true
	for err != nil {
		errDetails := ""
		dErr, ok := errors.AsType[xerrors.DetailedError](err)
		if ok {
			errDetails = dErr.ErrorDetails()
		}
		if errDetails != "" {
			if first {
				buf.WriteString("Error: ")
			}
			buf.WriteString(err.Error() + "\n")
		}
		first = false
		err = errors.Unwrap(err)
	}

	if buf.Len() != 0 {
		_, _ = fmt.Fprint(os.Stderr, buf.String())
	}
}
