package utils

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateDg1Hash(t *testing.T) {
	tests := []struct {
		name      string
		inputHash []byte
		expected  [32]byte
	}{
		{
			name:      "16-byte hash",
			inputHash: bytes.Repeat([]byte{0xDD}, 16), // Example: 16 bytes of 0xDD
			expected: func() [32]byte {
				var result [32]byte
				copy(result[32-16:], bytes.Repeat([]byte{0xDD}, 32))
				return result
			}(),
		},
		{
			name:      "20-byte hash",
			inputHash: bytes.Repeat([]byte{0xAA}, 20), // Example: 20 bytes of 0xAA
			expected: func() [32]byte {
				var result [32]byte
				copy(result[32-20:], bytes.Repeat([]byte{0xAA}, 32))
				return result
			}(),
		},
		{
			name:      "32-byte hash",
			inputHash: bytes.Repeat([]byte{0xBB}, 32), // Example: 32 bytes of 0xBB
			expected: func() [32]byte {
				var result [32]byte
				copy(result[1:], bytes.Repeat([]byte{0xBB}, 32))
				return result
			}(),
		},
		{
			name:      "48-byte hash",
			inputHash: bytes.Repeat([]byte{0xBB}, 48), // Example: 48 bytes of 0xBB
			expected: func() [32]byte {
				var result [32]byte
				copy(result[1:], bytes.Repeat([]byte{0xBB}, 32))
				return result
			}(),
		},
		{
			name:      "64-byte hash",
			inputHash: bytes.Repeat([]byte{0xCC}, 64), // Example: 64 bytes of 0xCC
			expected: func() [32]byte {
				var result [32]byte
				copy(result[1:], bytes.Repeat([]byte{0xCC}, 32))
				return result
			}(),
		},
		{
			name:      "128-byte hash",
			inputHash: bytes.Repeat([]byte{0xCC}, 128), // Example: 128 bytes of 0xCC (I don't know if this even possible, but just in case)
			expected: func() [32]byte {
				var result [32]byte
				copy(result[1:], bytes.Repeat([]byte{0xCC}, 32))
				return result
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateDg1Hash(tt.inputHash)
			t.Logf("Input Hash: \t\t0x%X", tt.inputHash)
			t.Logf("Truncated Result:\t0x%X", result)
			assert.Equal(t, tt.expected, result, "Truncated hash should match expected value")
		})
	}
}
