package randutil

import "crypto/rand"

func RandNBytes(n int) []byte {
	bs := make([]byte, n)
	n, _ = rand.Read(bs)
	return bs
}

func RandBytes(bs []byte) int {
	n, _ := rand.Read(bs)
	return n
}
