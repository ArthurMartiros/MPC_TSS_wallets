package approval

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"thresholdvault/internal/identity"
)

func TestIssueVerify(t *testing.T) {
	user, _ := identity.Generate("user")
	now := time.Unix(1_800_000_000, 0)
	want := Claims{TxID: "tx_1", WalletID: "w_1", Chain: "ethereum-sepolia", Sighash: "AB12"}
	tok, claims, err := Issue(user, want, now, DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Signer != "user" || claims.ExpiresAt != now.Add(time.Hour).Unix() {
		t.Fatalf("claims %+v", claims)
	}
	if _, err := Verify(tok, &user.Public, want, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	mallory, _ := identity.Generate("user") // same name, different key
	other := func(f func(*Claims)) Claims { c := want; f(&c); return c }
	cases := map[string]struct {
		approver *identity.Public
		want     Claims
		at       time.Time
	}{
		"wrong key":        {&mallory.Public, want, now},
		"other tx":         {&user.Public, other(func(c *Claims) { c.TxID = "tx_2" }), now},
		"other wallet":     {&user.Public, other(func(c *Claims) { c.WalletID = "w_2" }), now},
		"other chain":      {&user.Public, other(func(c *Claims) { c.Chain = "bsc-testnet" }), now},
		"changed contents": {&user.Public, other(func(c *Claims) { c.Sighash = "ab13" }), now},
		"expired":          {&user.Public, want, now.Add(2 * time.Hour)},
	}
	for name, tc := range cases {
		if _, err := Verify(tok, tc.approver, tc.want, tc.at); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	server, _ := identity.Generate("server")
	srvTok, _, _ := Issue(server, want, now, DefaultTTL)
	if _, err := Verify(srvTok, &user.Public, want, now); err == nil || !strings.Contains(err.Error(), "issued by") {
		t.Errorf("token from another signer accepted: %v", err)
	}
	if _, err := Verify("not-a-token", &user.Public, want, now); err == nil {
		t.Error("garbage accepted")
	}
}

func TestTamperedClaimsRejected(t *testing.T) {
	user, _ := identity.Generate("user")
	now := time.Now()
	want := Claims{TxID: "tx_1", WalletID: "w_1", Chain: "c", Sighash: "aa"}
	tok, _, _ := Issue(user, want, now, time.Minute)
	c, sig, _ := Parse(tok)
	// Extend the expiry but keep the original signature.
	c.ExpiresAt += 3600
	raw, _ := json.Marshal(token{Claims: *c, Sig: sig})
	forged := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Verify(forged, &user.Public, want, now.Add(30*time.Minute)); err == nil {
		t.Fatal("token with modified expiry accepted")
	}
}
