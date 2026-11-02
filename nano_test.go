package nano

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

func h(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t *testing.T, name string, v interface{}) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

type vectors struct {
	Blake2b []struct {
		In   string
		Size int
		Out  string
	}
	Accounts []struct {
		Seed    string `json:"seed_hex"`
		Index   uint32
		Private string `json:"private_hex"`
		Public  string
		Address string
	}
	Signatures []struct {
		Private   string `json:"private_hex"`
		Public    string
		Message   string
		Signature string
	}
}

func TestBlake2bMatchesReference(t *testing.T) {
	var v vectors
	load(t, "vectors.json", &v)
	for _, c := range v.Blake2b {
		if got := hex.EncodeToString(Blake2b(c.Size, h(t, c.In))); got != c.Out {
			t.Fatalf("len %d size %d: got %s want %s", len(c.In)/2, c.Size, got, c.Out)
		}
	}
	// RFC 7693 Appendix A: BLAKE2b-512("abc")
	want := "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
	if got := hex.EncodeToString(Blake2b(64, []byte("abc"))); got != want {
		t.Fatalf("RFC 7693 vector: %s", got)
	}
}

func TestOfficialZeroSeedVector(t *testing.T) {
	// docs.nano.org: seed of 32 zero bytes, index 0.
	priv, _ := PrivateKeyFromSeed(make([]byte, 32), 0)
	if hex.EncodeToString(priv) != strings.ToLower("9F0E444C69F77A49BD0BE89DB92C38FE713E0963165CCA12FAF5712D7657120F") {
		t.Fatal("private key differs from the official vector")
	}
	pub, _ := PublicKey(priv)
	if hex.EncodeToString(pub) != strings.ToLower("C008B814A7D269A1FA3C6528B19201A24D797912DB9996FF02A1FF356E45552B") {
		t.Fatal("public key differs from the official vector")
	}
	if EncodeAddress(pub) != "nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7" {
		t.Fatal("address differs from the official vector")
	}
}

func TestAccountsAndAddresses(t *testing.T) {
	var v vectors
	load(t, "vectors.json", &v)
	for _, a := range v.Accounts {
		priv, _ := PrivateKeyFromSeed(h(t, a.Seed), a.Index)
		if hex.EncodeToString(priv) != a.Private {
			t.Fatalf("private key index %d", a.Index)
		}
		pub, _ := PublicKey(priv)
		if hex.EncodeToString(pub) != a.Public {
			t.Fatalf("public key index %d", a.Index)
		}
		if got := EncodeAddress(pub); got != a.Address {
			t.Fatalf("address: %s != %s", got, a.Address)
		}
		back, err := DecodeAddress(a.Address)
		if err != nil || !bytes.Equal(back, pub) {
			t.Fatalf("round trip: %v", err)
		}
		if _, err := DecodeAddress("xrb_" + a.Address[5:]); err != nil {
			t.Fatalf("xrb_ prefix: %v", err)
		}
	}
}

func TestAddressRefusals(t *testing.T) {
	good := "nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7"
	flip := good[:len(good)-1] + "3"
	cases := map[string]error{
		flip:                              ErrAddressChecksum,
		"nano_" + good[5:30]:              ErrAddressFormat,
		"btc_" + good[5:]:                 ErrAddressFormat,
		good[:10] + "0" + good[11:]:       ErrAddressAlphabet,
		good[:10] + "l" + good[11:]:       ErrAddressAlphabet,
		good[:10] + "v" + good[11:]:       ErrAddressAlphabet,
		"nano_" + strings.Repeat("z", 60): ErrAddressFormat, // pad bits non-zero
	}
	for in, want := range cases {
		if _, err := DecodeAddress(in); err != want {
			t.Errorf("%q: got %v want %v", in, err, want)
		}
	}
	// every single-character substitution in the body must fail
	for i := 5; i < len(good); i++ {
		for _, r := range alphabet {
			if byte(r) == good[i] {
				continue
			}
			bad := good[:i] + string(r) + good[i+1:]
			if _, err := DecodeAddress(bad); err == nil {
				t.Fatalf("substitution at %d accepted", i)
			}
		}
	}
}

func TestSignaturesDeterministicAndVerify(t *testing.T) {
	var v vectors
	load(t, "vectors.json", &v)
	for _, s := range v.Signatures {
		sig, _ := Sign(h(t, s.Message), h(t, s.Private))
		if hex.EncodeToString(sig) != s.Signature {
			t.Fatalf("signature differs from the reference")
		}
		if !Verify(h(t, s.Message), sig, h(t, s.Public)) {
			t.Fatal("own signature fails")
		}
		bad := append([]byte(nil), sig...)
		bad[10] ^= 1
		if Verify(h(t, s.Message), bad, h(t, s.Public)) {
			t.Fatal("tampered R accepted")
		}
		bad = append([]byte(nil), sig...)
		bad[40] ^= 1
		if Verify(h(t, s.Message), bad, h(t, s.Public)) {
			t.Fatal("tampered S accepted")
		}
		m := h(t, s.Message)
		m[0] ^= 1
		if Verify(m, sig, h(t, s.Public)) {
			t.Fatal("other message accepted")
		}
	}
}

func TestNonCanonicalSRefused(t *testing.T) {
	var v vectors
	load(t, "vectors.json", &v)
	s := v.Signatures[0]
	sig := h(t, s.Signature)
	// S + L is the same point equation but malleable; must be refused.
	sv := fromLE(sig[32:])
	sv.Add(sv, edL)
	if sv.BitLen() > 256 {
		t.Skip("S+L overflows 32 bytes for this vector")
	}
	mal := append(append([]byte(nil), sig[:32]...), le32(sv)...)
	if Verify(h(t, s.Message), mal, h(t, s.Public)) {
		t.Fatal("malleable signature accepted")
	}
	if Verify(h(t, s.Message), sig[:63], h(t, s.Public)) || Verify(h(t, s.Message), sig, h(t, s.Public)[:31]) {
		t.Fatal("short input accepted")
	}
}

type mainnetBlock struct {
	Hash, Subtype, Account, Previous, Representative, Balance, Link, Signature, Work string
	LinkAsAccount                                                                    string `json:"link_as_account"`
}

func (m mainnetBlock) block(t *testing.T) StateBlock {
	acct, err := DecodeAddress(m.Account)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := DecodeAddress(m.Representative)
	if err != nil {
		t.Fatal(err)
	}
	bal, _ := new(big.Int).SetString(m.Balance, 10)
	return StateBlock{Account: acct, Previous: h(t, m.Previous), Representative: rep, Balance: bal, Link: h(t, m.Link)}
}

func TestRealMainnetBlocks(t *testing.T) {
	var f struct{ Blocks []mainnetBlock }
	load(t, "mainnet.json", &f)
	for _, m := range f.Blocks {
		b := m.block(t)
		hash, err := b.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if strings.ToUpper(hex.EncodeToString(hash)) != m.Hash {
			t.Fatalf("%s: block hash recomputed as %X", m.Subtype, hash)
		}
		ok, _ := b.VerifySignature(h(t, m.Signature))
		if !ok {
			t.Fatalf("%s: the network's own signature fails", m.Subtype)
		}
		la, _ := DecodeAddress(m.LinkAsAccount)
		if !bytes.Equal(la, b.Link) {
			t.Fatalf("%s: link_as_account does not decode to link", m.Subtype)
		}
		// a different amount changes the hash, so the signature must fail
		b2 := b
		b2.Balance = new(big.Int).Add(b.Balance, big.NewInt(1))
		if ok, _ := b2.VerifySignature(h(t, m.Signature)); ok {
			t.Fatalf("%s: signature accepted for a different balance", m.Subtype)
		}
		root := b.WorkRoot()
		thr := ReceiveThreshold
		if m.Subtype == "send" {
			thr = SendThreshold
		}
		if !WorkValid(root, m.Work, thr) {
			t.Fatalf("%s: network work rejected", m.Subtype)
		}
		if WorkValid(root, m.Work[:15]+"0", thr) && m.Work[15] != '0' {
			t.Fatalf("%s: flipped work still valid", m.Subtype)
		}
		if WorkValid(make([]byte, 32), m.Work, thr) {
			t.Fatalf("%s: work valid for another root", m.Subtype)
		}
		if m.Subtype == "open" {
			if WorkValid(root, m.Work, SendThreshold) {
				t.Fatal("receive-grade work passed the send threshold")
			}
			if !bytes.Equal(root, b.Account) {
				t.Fatal("open block work root must be the account key")
			}
		}
	}
}

func TestWorkMalformedIsInvalidNotPanic(t *testing.T) {
	root := make([]byte, 32)
	for _, w := range []string{"", "ff", "zzzzzzzzzzzzzzzz", "58fc8abfa35fcfeeff"} {
		if WorkValid(root, w, 0) {
			t.Errorf("%q valid", w)
		}
	}
	if _, err := WorkDifficulty(root[:5], "58fc8abfa35fcfee"); err == nil {
		t.Error("short root accepted")
	}
}

func TestBalanceRange(t *testing.T) {
	b := StateBlock{Account: make([]byte, 32), Previous: make([]byte, 32), Representative: make([]byte, 32), Link: make([]byte, 32)}
	b.Balance = new(big.Int).Add(MaxBalanceRaw, big.NewInt(1))
	if _, err := b.Hash(); err == nil {
		t.Fatal("2^128 accepted")
	}
	b.Balance = big.NewInt(-1)
	if _, err := b.Hash(); err == nil {
		t.Fatal("negative accepted")
	}
	b.Balance = MaxBalanceRaw
	if _, err := b.Hash(); err != nil {
		t.Fatal(err)
	}
}
