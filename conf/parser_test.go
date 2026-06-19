package conf

import (
	"testing"

	"github.com/shoenig/test/must"
)

func TestValidateClientConfig(t *testing.T) {
	_, err := Parse("../client_example.conf.json")
	must.NoError(t, err)
}

func TestValidateServerConfig(t *testing.T) {
	_, err := Parse("../client_example.conf.json")
	must.NoError(t, err)
}
