package chain

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// ParseAmount converts a human decimal string ("1.5") into base units for an
// asset with the given decimals (1.5 USDC, 6 decimals -> 1500000). It is exact:
// no floating point, and more fractional digits than the asset supports is an
// error rather than a silent truncation.
func ParseAmount(s string, decimals uint8) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("amount is empty")
	}
	whole, frac, hasDot := strings.Cut(s, ".")
	if hasDot && frac == "" || whole == "" && frac == "" {
		return nil, fmt.Errorf("invalid amount %q", s)
	}
	for _, part := range []string{whole, frac} {
		for _, r := range part {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("invalid amount %q: only digits and one '.' are allowed", s)
			}
		}
	}
	if len(frac) > int(decimals) {
		return nil, fmt.Errorf("amount %q has more than %d decimal places", s, decimals)
	}
	v, ok := new(big.Int).SetString(whole+frac+strings.Repeat("0", int(decimals)-len(frac)), 10)
	if !ok {
		return nil, fmt.Errorf("invalid amount %q", s)
	}
	if v.Sign() <= 0 {
		return nil, errors.New("amount must be greater than zero")
	}
	return v, nil
}

// FormatAmount renders base units as a decimal string without trailing
// zeros (1500000 with 6 decimals -> "1.5").
func FormatAmount(v *big.Int, decimals uint8) string {
	if v == nil {
		return "0"
	}
	neg := v.Sign() < 0
	s := new(big.Int).Abs(v).String()
	if d := int(decimals); d > 0 {
		if len(s) <= d {
			s = strings.Repeat("0", d-len(s)+1) + s
		}
		s = s[:len(s)-d] + "." + s[len(s)-d:]
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	if neg {
		s = "-" + s
	}
	return s
}
