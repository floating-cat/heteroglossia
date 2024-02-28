//go:build !(darwin || linux)

package proxy

import (
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/errors"
)

func SetSystemProxy(_ string, _ uint16, _ *transport.HTTPSOCKSAuthInfo) (unsetProxy func(), err error) {
	return nil, errors.New("doesn't support the system proxy in this OS")
}
