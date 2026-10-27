package http

import (
	_ "unsafe"
)

//go:linkname parseBasicAuth net/http.parseBasicAuth
func parseBasicAuth(_ string) (username, password string, ok bool)
