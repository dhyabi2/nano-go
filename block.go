package nano

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// StatePreamble is the 32-byte big-endian 6 that opens every state-block hash.
var StatePreamble = func() []byte { p := make([]byte, 32); p[31] = 6; return p }()

// MaxBalanceRaw is 2^128-1, the largest value the 16-byte balance field holds.
var MaxBalanceRaw = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))

// StateBlock is the six fields a state-block hash commits to.
type StateBlock struct {
	Account        []byte // 32-byte public key
	Previous       []byte // 32 bytes, all zero for an account's first block
	Representative []byte // 32-byte public key
	Balance        *big.Int
	Link           []byte // 32 bytes: destination key (send) or source hash (receive)
}

// Hash is blake2b-256(preamble || account || previous || representative ||
// balance(16, big-endian) || link).
func (b StateBlock) Hash() ([]byte, error) {
	for _, f := range [][]byte{b.Account, b.Previous, b.Representative, b.Link} {
		if len(f) != 32 {
			return nil, errors.New("nano: block fields must be 32 bytes")
		}
	}
	if b.Balance == nil || b.Balance.Sign() < 0 || b.Balance.Cmp(MaxBalanceRaw) > 0 {
		return nil, errors.New("nano: balance out of range for a 128-bit raw field")
	}
	bal := make([]byte, 16)
	b.Balance.FillBytes(bal)
	return Blake2b(32, StatePreamble, b.Account, b.Previous, b.Representative, bal, b.Link), nil
}

// VerifySignature checks sig over the block hash against the block's account.
func (b StateBlock) VerifySignature(sig []byte) (bool, error) {
	h, err := b.Hash()
	if err != nil {
		return false, err
	}
	return Verify(h, sig, b.Account), nil
}

// WorkRoot is what proof of work is computed over: the previous hash, or the
// account key for an account's first block.
func (b StateBlock) WorkRoot() []byte {
	for _, c := range b.Previous {
		if c != 0 {
			return b.Previous
		}
	}
	return b.Account
}

// Epoch-2 work thresholds. A send or change needs 64x a receive or open.
const (
	SendThreshold    uint64 = 0xFFFFFFF800000000
	ReceiveThreshold uint64 = 0xFFFFFE0000000000
)

// WorkDifficulty is blake2b-64(work reversed || root) read little-endian.
// work is the 8 bytes in the order the 16-hex-character field spells them.
func WorkDifficulty(root []byte, workHex string) (uint64, error) {
	w, err := hex.DecodeString(strings.TrimSpace(workHex))
	if err != nil || len(w) != 8 {
		return 0, errors.New("nano: work must be 16 hex characters")
	}
	if len(root) != 32 {
		return 0, errors.New("nano: root must be 32 bytes")
	}
	rev := make([]byte, 8)
	for i := range w {
		rev[7-i] = w[i]
	}
	return binary.LittleEndian.Uint64(Blake2b(8, rev, root)), nil
}

// WorkValid reports whether workHex meets threshold for root. Malformed
// input is simply invalid, never a panic.
func WorkValid(root []byte, workHex string, threshold uint64) bool {
	d, err := WorkDifficulty(root, workHex)
	return err == nil && d >= threshold
}
