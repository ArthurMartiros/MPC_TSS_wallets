package identity

import (
	"bytes"
	"testing"
)

func TestPublicRoundTripAndFingerprint(t *testing.T) {
	id, err := Generate("server")
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePublic(id.Public.String())
	if err != nil {
		t.Fatal(err)
	}
	if !p.Equal(&id.Public) || p.Fingerprint() != id.Fingerprint() {
		t.Fatal("public identity did not round-trip")
	}
	for _, bad := range []string{"", "tvid1:", "tvid1:x:!!", "nope:server:AAAA", "tvid1:server:AAAA"} {
		if _, err := ParsePublic(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
	if _, err := Generate("bad:name"); err == nil {
		t.Error("accepted name with colon")
	}
}

func TestPrivateRoundTrip(t *testing.T) {
	id, _ := Generate("user")
	raw, err := id.MarshalPrivate()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalPrivate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(&id.Public) {
		t.Fatal("private identity did not round-trip")
	}
	msg := []byte("hello")
	if !id.Verify(msg, back.Sign(msg)) {
		t.Fatal("restored key signs differently")
	}
}

func TestSealOpenAndSignVerify(t *testing.T) {
	a, _ := Generate("a")
	b, _ := Generate("b")
	c, _ := Generate("c")
	nonce, box, err := a.Seal(&b.Public, []byte("share"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := b.Open(&a.Public, nonce, box)
	if err != nil || !bytes.Equal(pt, []byte("share")) {
		t.Fatalf("open: %v %q", err, pt)
	}
	if _, err := c.Open(&a.Public, nonce, box); err == nil {
		t.Fatal("third party opened the box")
	}
	if _, err := b.Open(&c.Public, nonce, box); err == nil {
		t.Fatal("box accepted with wrong sender key")
	}
	sig := a.Sign([]byte("m"))
	if !a.Verify([]byte("m"), sig) || b.Verify([]byte("m"), sig) || a.Verify([]byte("x"), sig) {
		t.Fatal("signature verification wrong")
	}
}
