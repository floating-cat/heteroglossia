package tr_carrier

import (
	"testing"

	"github.com/shoenig/test/must"
)

func TestEscapeLineBreaks(t *testing.T) {
	tests := []struct {
		arr      [16]byte
		expected [16]byte
	}{
		{[16]byte{1, 2, 3, 4}, [16]byte{1, 2, 3, 4}},
		{[16]byte{cr, 2, 3, 4}, [16]byte{escapedCR, 2, 3, 4}},
		{[16]byte{cr, 2, cr, 4}, [16]byte{escapedCR, 2, escapedCR, 4}},
	}
	for _, tt := range tests {
		must.Eq(t, tt.expected, escapeLineBreaks(tt.arr), must.Sprintf("no match: %v", tt))
	}
}
