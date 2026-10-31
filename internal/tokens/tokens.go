// Package tokens makes and checks Valet's bearer tokens.
//
// A token is a prefix naming its kind (RFC decision 11) followed by 256
// random bits in lowercase base32: vlt_sess_… for agent sessions, vlt_admin_…
// for operators, vlt_enroll_… for one-time enrollment codes (#19). One
// "vlt_" pattern lets secret scanners catch every Valet token. Only a
// SHA-256 of a token is ever stored; the plaintext is shown once.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"
)

// Kind is a token's type, carried in its prefix.
type Kind string

// Token kinds.
const (
	Session Kind = "vlt_sess_"
	Admin   Kind = "vlt_admin_"
	Enroll  Kind = "vlt_enroll_"
)

const randomBytes = 32

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// encodedLen is the length of the random part.
var encodedLen = encoding.EncodedLen(randomBytes)

// ErrMalformed is returned for a string that isn't a well-formed token of the
// expected kind. It says nothing about which part is wrong.
var ErrMalformed = errors.New("malformed token")

// New returns a fresh token of kind k and its hash for storage.
func New(k Kind) (string, []byte, error) {
	b := make([]byte, randomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	tok := string(k) + strings.ToLower(encoding.EncodeToString(b))
	return tok, Hash(tok), nil
}

// Hash is the stored form of a token.
func Hash(tok string) []byte {
	sum := sha256.Sum256([]byte(tok))
	return sum[:]
}

// Parse checks that tok is a well-formed token of kind k and returns its
// hash. A token of another kind is malformed here: an admin token is never a
// session token, and the reverse.
func Parse(k Kind, tok string) ([]byte, error) {
	rest, ok := strings.CutPrefix(tok, string(k))
	if !ok || len(rest) != encodedLen {
		return nil, ErrMalformed
	}
	for _, c := range rest {
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return nil, ErrMalformed
		}
	}
	return Hash(tok), nil
}
