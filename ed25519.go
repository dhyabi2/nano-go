package nano

import (
	"errors"
	"math/big"
)

// Ed25519 as RFC 8032 specifies it, with BLAKE2b-512 in place of SHA-512
// (Nano's variant). Written with math/big for clarity: it is NOT constant
// time. Verify handles only public data and is safe to use anywhere; Sign
// touches a private key and must not run where a timing side channel
// matters (a shared host with an attacker). See AUDIT-NOTE.md.

var (
	edQ = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edL = func() *big.Int {
		l, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
		return l.Add(l, new(big.Int).Lsh(big.NewInt(1), 252))
	}()
	edD  = new(big.Int)
	edI  = new(big.Int)
	edB  [2]*big.Int
	one  = big.NewInt(1)
	zero = big.NewInt(0)
)

func init() {
	inv121666 := new(big.Int).ModInverse(big.NewInt(121666), edQ)
	edD.Mul(big.NewInt(-121665), inv121666).Mod(edD, edQ)
	edI.Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edQ, one), 2), edQ)
	by := new(big.Int).Mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), edQ))
	by.Mod(by, edQ)
	bx, _ := recoverX(by)
	edB = [2]*big.Int{bx, by}
}

func recoverX(y *big.Int) (*big.Int, bool) {
	yy := new(big.Int).Mul(y, y)
	num := new(big.Int).Sub(yy, one)
	den := new(big.Int).Mul(edD, yy)
	den.Add(den, one)
	xx := new(big.Int).Mul(num, new(big.Int).ModInverse(den, edQ))
	xx.Mod(xx, edQ)
	e := new(big.Int).Add(edQ, big.NewInt(3))
	e.Rsh(e, 3)
	x := new(big.Int).Exp(xx, e, edQ)
	chk := new(big.Int).Mul(x, x)
	chk.Sub(chk, xx).Mod(chk, edQ)
	if chk.Sign() != 0 {
		x.Mul(x, edI).Mod(x, edQ)
	}
	chk.Mul(x, x).Sub(chk, xx).Mod(chk, edQ)
	if chk.Sign() != 0 {
		return nil, false
	}
	if x.Bit(0) == 1 {
		x.Sub(edQ, x)
	}
	return x, true
}

type pt [2]*big.Int

func edAdd(p, q pt) pt {
	t := new(big.Int).Mul(p[0], q[0])
	t.Mul(t, p[1]).Mul(t, q[1]).Mul(t, edD).Mod(t, edQ)
	x := new(big.Int).Mul(p[0], q[1])
	x.Add(x, new(big.Int).Mul(q[0], p[1]))
	d1 := new(big.Int).Add(one, t)
	x.Mul(x, d1.ModInverse(d1, edQ)).Mod(x, edQ)
	y := new(big.Int).Mul(p[1], q[1])
	y.Add(y, new(big.Int).Mul(p[0], q[0]))
	d2 := new(big.Int).Sub(one, t)
	d2.Mod(d2, edQ)
	y.Mul(y, d2.ModInverse(d2, edQ)).Mod(y, edQ)
	return pt{x, y}
}

func edMul(p pt, e *big.Int) pt {
	r := pt{new(big.Int), big.NewInt(1)}
	for i := e.BitLen() - 1; i >= 0; i-- {
		r = edAdd(r, r)
		if e.Bit(i) == 1 {
			r = edAdd(r, p)
		}
	}
	return r
}

func encodePoint(p pt) []byte {
	out := le32(p[1])
	out[31] |= byte(p[0].Bit(0)) << 7
	return out
}

func decodePoint(b []byte) (pt, bool) {
	if len(b) != 32 {
		return pt{}, false
	}
	c := append([]byte(nil), b...)
	sign := c[31] >> 7
	c[31] &= 0x7f
	y := fromLE(c)
	if y.Cmp(edQ) >= 0 {
		return pt{}, false
	}
	x, ok := recoverX(y)
	if !ok {
		return pt{}, false
	}
	if x.Sign() == 0 && sign == 1 {
		return pt{}, false
	}
	if uint(sign) != x.Bit(0) {
		x.Sub(edQ, x)
	}
	return pt{x, y}, true
}

func fromLE(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func le32(v *big.Int) []byte {
	be := v.Bytes()
	out := make([]byte, 32)
	for i := range be {
		out[i] = be[len(be)-1-i]
	}
	return out
}

func clamp(h []byte) *big.Int {
	c := append([]byte(nil), h[:32]...)
	c[0] &= 248
	c[31] &= 127
	c[31] |= 64
	return fromLE(c)
}

// PublicKey derives the 32-byte public key of a 32-byte private key.
func PublicKey(priv []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("nano: private key must be 32 bytes")
	}
	return encodePoint(edMul(pt(edB), clamp(Blake2b(64, priv)))), nil
}

// PrivateKeyFromSeed is Nano's derivation: blake2b-256(seed || index_be32).
func PrivateKeyFromSeed(seed []byte, index uint32) ([]byte, error) {
	if len(seed) != 32 {
		return nil, errors.New("nano: seed must be 32 bytes")
	}
	return Blake2b(32, seed, []byte{byte(index >> 24), byte(index >> 16), byte(index >> 8), byte(index)}), nil
}

// Sign returns the 64-byte signature of msg. NOT constant time (see file note).
func Sign(msg, priv []byte) ([]byte, error) {
	pub, err := PublicKey(priv)
	if err != nil {
		return nil, err
	}
	h := Blake2b(64, priv)
	a := clamp(h)
	r := fromLE(Blake2b(64, h[32:64], msg))
	r.Mod(r, edL)
	R := encodePoint(edMul(pt(edB), r))
	k := fromLE(Blake2b(64, R, pub, msg))
	k.Mod(k, edL)
	s := new(big.Int).Mul(k, a)
	s.Add(s, r).Mod(s, edL)
	return append(R, le32(s)...), nil
}

// Verify reports whether sig is a valid signature of msg under pub. It
// rejects a non-canonical S (>= L) and a public key or R that is not a
// curve point. Only public data is touched.
func Verify(msg, sig, pub []byte) bool {
	if len(sig) != 64 || len(pub) != 32 {
		return false
	}
	A, ok := decodePoint(pub)
	if !ok {
		return false
	}
	R, ok := decodePoint(sig[:32])
	if !ok {
		return false
	}
	s := fromLE(sig[32:])
	if s.Cmp(edL) >= 0 {
		return false
	}
	k := fromLE(Blake2b(64, sig[:32], pub, msg))
	k.Mod(k, edL)
	lhs := edMul(pt(edB), s)
	rhs := edAdd(R, edMul(A, k))
	return lhs[0].Cmp(rhs[0]) == 0 && lhs[1].Cmp(rhs[1]) == 0
}
