// Package grant issues, loads, and checks one sahxfer grant.
//
// Threats: a grant that authorizes the wrong host, root, path, size, or
// hash; a size that does not fit a signed 64-bit length; a key or route
// token that is the wrong width; a bootstrap file the group can read.
// Callers get a code and never a wrapped encoding error, because that
// text can quote the key. Go strings inside a decoded document cannot be
// wiped. Byte slices are wiped.
package grant

import (
	"strconv"

	"github.com/afterdarksys/sahxfer/internal/code"
)

// Uint64 is a JSON integer with no fraction, exponent, sign, or leading zero.
// A float64 decode would round sizes above 2^53.
type Uint64 uint64

func (u Uint64) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatUint(uint64(u), 10)), nil
}

func (u *Uint64) UnmarshalJSON(b []byte) error {
	n, err := ParseUint(string(b))
	if err != nil {
		return err
	}
	*u = Uint64(n)
	return nil
}

// ParseUint accepts digits only. "0" is zero. "01", "1.0", and "1e2" are bad_grant.
func ParseUint(s string) (uint64, error) {
	if s == "" || len(s) > 20 {
		return 0, code.New("bad_grant")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, code.New("bad_grant")
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, code.New("bad_grant")
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, code.New("bad_grant")
	}
	return n, nil
}
