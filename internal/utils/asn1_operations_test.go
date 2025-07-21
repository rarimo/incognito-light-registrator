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

func TestExtractFirstNBits(t *testing.T) {

	customHash := []byte{0x0F, 0xF0, 0xAA, 0x55}

	sha1hash := []byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0xFA,
		0xCE, 0xCA, 0xFE, 0xBA, 0xBE,
		0x00, 0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88, 0x99,
	} // 20 bytes (160 bits)

	cases := []struct {
		inputHash []byte
		nBits     uint
		expected  []byte
	}{
		{customHash, 4, []byte{0x00}},                                // upper 4 bits 0000
		{customHash, 8, []byte{0x0F}},                                // first byte
		{customHash, 9, []byte{0x0F, 0x80}},                          // 8 bits + 1 from the next byte
		{customHash, 12, []byte{0x0F, 0xF0}},                         // 12 bits (1.5 bytes)
		{customHash, 16, []byte{0x0F, 0xF0}},                         // full 2 bytes
		{customHash, 32, customHash},                                 // full input
		{customHash, 47, []byte{0x0F, 0xF0, 0xAA, 0x55, 0x00, 0x00}}, // 5 bytes - 1 bit
		{customHash, 48, []byte{0x0F, 0xF0, 0xAA, 0x55, 0x00, 0x00}}, // 5 bytes

		{sha1hash, 0, []byte{}},
		{sha1hash, 1, []byte{0x80}},
		{sha1hash, 7, []byte{0xDE}},
		{sha1hash, 8, []byte{0xDE}},
		{sha1hash, 9, []byte{0xDE, 0x80}},
		{sha1hash, 15, []byte{0xDE, 0xAC}},
		{sha1hash, 16, []byte{0xDE, 0xAD}},
		{sha1hash, 17, []byte{0xDE, 0xAD, 0x80}},
		{sha1hash, 20, []byte{0xDE, 0xAD, 0xB0}},
		{sha1hash, 32, []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{sha1hash, 158, append(sha1hash[:19], 0x98)},
		{sha1hash, 159, append(sha1hash[:19], 0x98)},
		{sha1hash, 160, sha1hash},
		{sha1hash, 200, append(sha1hash, bytes.Repeat([]byte{0x00}, 5)...)}, // pad to 25 bytes
		{sha1hash, 252, append(sha1hash, bytes.Repeat([]byte{0x00}, 12)...)},
	}

	for _, tc := range cases {
		result, err := ExtractFirstNBits(tc.inputHash, tc.nBits)
		t.Logf("Input: \t\t0x%X", tc.inputHash)
		t.Logf("Extracted output: \t\t0x%X", result)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, result, "failed on %d bits", tc.nBits)
	}

}

func TestReverseBits(t *testing.T) {
	tests := []struct {
		input    []byte
		expected []byte
	}{
		{[]byte{0x00}, []byte{0x00}}, // 00000000 → 00000000
		{[]byte{0xFF}, []byte{0xFF}}, // 11111111 → 11111111
		{[]byte{0x01}, []byte{0x80}}, // 00000001 → 10000000
		{[]byte{0x02}, []byte{0x40}}, // 00000010 → 01000000
		{[]byte{0x03}, []byte{0xC0}}, // 00000011 → 11000000
		{[]byte{0xAA}, []byte{0x55}}, // 10101010 → 01010101
		{[]byte{0x0F}, []byte{0xF0}}, // 00001111 → 11110000
		{[]byte{0xF0}, []byte{0x0F}}, // 11110000 → 00001111
		{[]byte{0x96, 0x3C}, []byte{0x3C, 0x69}},
		{[]byte{0x12, 0x34, 0x56}, []byte{0x6A, 0x2C, 0x48}},

		{[]byte{
			0x01, 0x23, 0x45, 0x67, 0x89,
			0xAB, 0xCD, 0xEF, 0x10, 0x32,
			0x54, 0x76, 0x98, 0xBA, 0xDC,
			0xFE, 0x11, 0x22, 0x33, 0x44,
		}, []byte{
			0x22, 0xCC, 0x44, 0x88, 0x7F,
			0x3B, 0x5D, 0x19, 0x6E, 0x2A,
			0x4C, 0x08, 0xF7, 0xB3, 0xD5,
			0x91, 0xE6, 0xA2, 0xC4, 0x80,
		}}, // 20-byte custom SHA-1-like

		{[]byte{
			0xDE, 0xAD, 0xBE, 0xEF, 0xFA,
			0xCE, 0xCA, 0xFE, 0xBA, 0xBE,
			0x00, 0x11, 0x22, 0x33, 0x44,
			0x55, 0x66, 0x77, 0x88, 0x99,
		}, []byte{
			0x99, 0x11, 0xEE, 0x66, 0xAA,
			0x22, 0xCC, 0x44, 0x88, 0x00,
			0x7D, 0x5D, 0x7F, 0x53, 0x73,
			0x5F, 0xF7, 0x7D, 0xB5, 0x7B,
		}},

		{bytes.Repeat([]byte{0x01}, 20), bytes.Repeat([]byte{0x80}, 20)}, // all 0x01 flipped → 0x80

		{bytes.Repeat([]byte{0x0F}, 32), bytes.Repeat([]byte{0xF0}, 32)}, // 32-byte input

		{bytes.Repeat([]byte{0xF0}, 64), bytes.Repeat([]byte{0x0F}, 64)}, // 64-byte input
	}

	for _, tt := range tests {
		result := ReverseBits(tt.input)
		assert.Equal(t, tt.expected, result, "input: %v", tt.input)
	}
}
