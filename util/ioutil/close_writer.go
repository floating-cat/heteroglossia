package ioutil

type CloseWriter interface {
	CloseWrite() error
}

func CloseWrite(conn any) error {
	cw, ok := conn.(CloseWriter)
	if !ok {
		return nil
	}
	return cw.CloseWrite()
}
