package chain

import (
	"math/big"
	"testing"
)

func TestParseAmount(t *testing.T) {
	cases := []struct {
		in   string
		dec  uint8
		want string
	}{
		{"1", 18, "1000000000000000000"},
		{"0.01", 18, "10000000000000000"},
		{"1.5", 6, "1500000"},
		{"1.500000", 6, "1500000"},
		{".5", 6, "500000"},
		{"0.000001", 6, "1"},
		{"123456789.12345678", 8, "12345678912345678"},
		{" 2 ", 0, "2"},
	}
	for _, c := range cases {
		got, err := ParseAmount(c.in, c.dec)
		if err != nil {
			t.Errorf("ParseAmount(%q, %d): %v", c.in, c.dec, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("ParseAmount(%q, %d) = %s, want %s", c.in, c.dec, got, c.want)
		}
	}
	for _, bad := range []struct {
		in  string
		dec uint8
	}{
		{"", 6}, {"0", 6}, {"0.0", 6}, {"-1", 6}, {"1e18", 18}, {"1.", 6}, {".", 6},
		{"1.2.3", 6}, {"0.0000001", 6}, {"1,5", 6}, {"abc", 6}, {"1.5", 0}, {"+1", 6},
	} {
		if v, err := ParseAmount(bad.in, bad.dec); err == nil {
			t.Errorf("ParseAmount(%q, %d) = %s, want error", bad.in, bad.dec, v)
		}
	}
}

func TestFormatAmount(t *testing.T) {
	cases := []struct {
		v    string
		dec  uint8
		want string
	}{
		{"1000000000000000000", 18, "1"},
		{"10000000000000000", 18, "0.01"},
		{"1500000", 6, "1.5"},
		{"1", 6, "0.000001"},
		{"0", 6, "0"},
		{"42", 0, "42"},
		{"-1500000", 6, "-1.5"},
	}
	for _, c := range cases {
		v, _ := new(big.Int).SetString(c.v, 10)
		if got := FormatAmount(v, c.dec); got != c.want {
			t.Errorf("FormatAmount(%s, %d) = %q, want %q", c.v, c.dec, got, c.want)
		}
	}
}

func TestParseFormatRoundTrip(t *testing.T) {
	for _, s := range []string{"1", "0.1", "123.456", "0.000000000000000001"} {
		v, err := ParseAmount(s, 18)
		if err != nil {
			t.Fatal(err)
		}
		if got := FormatAmount(v, 18); got != s {
			t.Errorf("round trip %q -> %q", s, got)
		}
	}
}
