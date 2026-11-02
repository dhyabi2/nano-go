package nano

import (
	"errors"
	"strings"
)

const alphabet = "13456789abcdefghijkmnopqrstuwxyz"

// Address errors carry a stable text so callers can switch on them.
var (
	ErrAddressFormat   = errors.New("nano: address must be nano_ or xrb_ plus 60 characters")
	ErrAddressAlphabet = errors.New("nano: character not in the Nano base32 alphabet (0, 2, l, v are never valid)")
	ErrAddressChecksum = errors.New("nano: address checksum mismatch")
)

func b32(v []byte, n int) string {
	// v is big-endian; emit n groups of 5 bits from the low end.
	out := make([]byte, n)
	var acc uint
	var nb uint
	idx := len(v) - 1
	for i := n - 1; i >= 0; i-- {
		for nb < 5 && idx >= 0 {
			acc |= uint(v[idx]) << nb
			nb += 8
			idx--
		}
		out[i] = alphabet[acc&31]
		acc >>= 5
		if nb >= 5 {
			nb -= 5
		} else {
			nb = 0
		}
	}
	return string(out)
}

func checksum(pub []byte) []byte {
	c := Blake2b(5, pub)
	for i, j := 0, len(c)-1; i < j; i, j = i+1, j-1 {
		c[i], c[j] = c[j], c[i]
	}
	return c
}

// EncodeAddress returns the nano_ address of a 32-byte public key.
func EncodeAddress(pub []byte) string {
	if len(pub) != 32 {
		panic("nano: public key must be 32 bytes")
	}
	padded := append([]byte{0}, pub...) // 4 zero pad bits fall out of 52*5=260 bits
	return "nano_" + b32(padded, 52) + b32(checksum(pub), 8)
}

// DecodeAddress parses and checksum-verifies an address (nano_ or xrb_).
func DecodeAddress(addr string) ([]byte, error) {
	a := strings.ToLower(strings.TrimSpace(addr))
	if strings.HasPrefix(a, "nano_") {
		a = a[5:]
	} else if strings.HasPrefix(a, "xrb_") {
		a = a[4:]
	} else {
		return nil, ErrAddressFormat
	}
	if len(a) != 60 {
		return nil, ErrAddressFormat
	}
	vals := make([]byte, 60)
	for i := 0; i < 60; i++ {
		k := strings.IndexByte(alphabet, a[i])
		if k < 0 {
			return nil, ErrAddressAlphabet
		}
		vals[i] = byte(k)
	}
	if vals[0] > 1 { // top 4 of the 260 bits are padding and must be zero
		return nil, ErrAddressFormat
	}
	// pack 52 groups into 260 bits -> 33 bytes, first byte is the pad.
	buf := make([]byte, 33)
	bitpos := 0
	for i := 0; i < 52; i++ {
		for b := 4; b >= 0; b-- {
			bit := (vals[i] >> uint(b)) & 1
			byteIdx := (bitpos + 4) / 8 // +4: left-pad to 264 bits
			buf[byteIdx] |= bit << uint(7-((bitpos+4)%8))
			bitpos++
		}
	}
	if buf[0] != 0 {
		return nil, ErrAddressFormat
	}
	pub := buf[1:]
	if b32(checksum(pub), 8) != a[52:] {
		return nil, ErrAddressChecksum
	}
	return pub, nil
}
