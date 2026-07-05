package strutil

import (
	"strconv"
)

func ToA(i uint16) string {
	return strconv.FormatUint(uint64(i), 10)
}
