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

	customHash := []byte{0b00001111, 0b11110000, 0b10101010, 0b1010101}

	sha1hash := []byte{
		0b11011110, 0b10101101, 0b10111110, 0b11101111, 0b11111010,
		0b11001110, 0b11001010, 0b11111110, 0b10111010, 0b10111110,
		0b00000000, 0b00010001, 0b00100010, 0b00110011, 0b01000100,
		0b01010101, 0b01100110, 0b01110111, 0b10001000, 0b10011001,
	} // 20 bytes (160 bits)

	cases := []struct {
		inputHash []byte
		nBits     uint
		expected  []byte
	}{
		{customHash, 4, []byte{0x00}},                                                       // upper 4 bits 0000
		{customHash, 8, []byte{0b00001111}},                                                 // first byte
		{customHash, 9, []byte{0b00001111, 0b10000000}},                                     // 8 bits + 1 from the next byte
		{customHash, 12, []byte{0b00001111, 0b11110000}},                                    // 12 bits (1.5 bytes)
		{customHash, 16, []byte{0b00001111, 0b11110000}},                                    // full 2 bytes
		{customHash, 32, customHash},                                                        // full input
		{customHash, 47, []byte{0b00001111, 0b11110000, 0b10101010, 0b1010101, 0x00, 0x00}}, // 5 bytes - 1 bit
		{customHash, 48, []byte{0b00001111, 0b11110000, 0b10101010, 0b1010101, 0x00, 0x00}}, // 5 bytes

		{sha1hash, 0, []byte{}},
		{sha1hash, 1, []byte{0b10000000}},
		{sha1hash, 7, []byte{0b11011110}},
		{sha1hash, 8, []byte{0b11011110}},
		{sha1hash, 9, []byte{0b11011110, 0b10000000}},
		{sha1hash, 15, []byte{0b11011110, 0b10101100}},
		{sha1hash, 16, []byte{0b11011110, 0b10101101}},
		{sha1hash, 17, []byte{0b11011110, 0b10101101, 0b10000000}},
		{sha1hash, 20, []byte{0b11011110, 0b10101101, 0b10110000}},
		{sha1hash, 32, []byte{0b11011110, 0b10101101, 0b10111110, 0b11101111}},
		{sha1hash, 158, append(sha1hash[:19], 0b10011000)},
		{sha1hash, 159, append(sha1hash[:19], 0b10011000)},
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
		{[]byte{0b00000000}, []byte{0b00000000}},
		{[]byte{0b11111111}, []byte{0b11111111}},
		{[]byte{0b00000001}, []byte{0b10000000}},
		{[]byte{0b00000010}, []byte{0b01000000}},
		{[]byte{0b00000011}, []byte{0b11000000}},
		{[]byte{0b10101010}, []byte{0b01010101}},
		{[]byte{0b00001111}, []byte{0b11110000}},
		{[]byte{0b11110000}, []byte{0b00001111}},
		{[]byte{0b10010110, 0b00111100}, []byte{0b00111100, 0b1101001}},
		{[]byte{0b00010010, 0b00110100, 0b1010110}, []byte{0b1101010, 0b101100, 0b1001000}},

		{[]byte{
			0b00000001, 0b00100011, 0b01000101, 0b1100111, 0b10001001,
			0b10101011, 0b11001101, 0b11101111, 0b00010000, 0b00110010,
			0b01010100, 0b01110110, 0b10011000, 0b10111010, 0b11011100,
			0b11111110, 0b00010001, 0b00100010, 0b00110011, 0b01000100,
		}, []byte{
			0b00100010, 0b11001100, 0b01000100, 0b10001000, 0b01111111,
			0b00111011, 0b01011101, 0b00011001, 0b01101110, 0b00101010,
			0b01001100, 0b00001000, 0b11110111, 0b10110011, 0b11010101,
			0b10010001, 0b11100110, 0b10100010, 0b11000100, 0b10000000,
		}}, // 20-byte custom SHA-1-like

		{[]byte{
			0b11011110, 0b10101101, 0b10111110, 0b11101111, 0b11111010,
			0b11001110, 0b11001010, 0b11111110, 0b10111010, 0b10111110,
			0b00000000, 0b00010001, 0b00100010, 0b00110011, 0b01000100,
			0b01010101, 0b01100110, 0b01110111, 0b10001000, 0b10011001,
		}, []byte{
			0b10011001, 0b00010001, 0b11101110, 0b01100110, 0b10101010,
			0b00100010, 0b11001100, 0b01000100, 0b10001000, 0b00000000,
			0b01111101, 0b01011101, 0b01111111, 0b01010011, 0b01110011,
			0b01011111, 0b11110111, 0b01111101, 0b10110101, 0b01111011,
		}},

		{bytes.Repeat([]byte{0b00000001}, 20), bytes.Repeat([]byte{0b10000000}, 20)},

		{bytes.Repeat([]byte{0b00001111}, 32), bytes.Repeat([]byte{0b11110000}, 32)}, // 32-byte input

		{bytes.Repeat([]byte{0b11110000}, 64), bytes.Repeat([]byte{0b00001111}, 64)}, // 64-byte input
	}

	for _, tt := range tests {
		result := ReverseBits(tt.input)
		assert.Equal(t, tt.expected, result, "input: %v", tt.input)
	}
}
