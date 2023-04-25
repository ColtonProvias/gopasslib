// Package totp is used to generate and verify Timed One-Time Passwords.
package totp

import (
	"encoding/base32"
	"errors"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const secretChunkSize = 4

var errUnimplemented = errors.New("unimplemented")

// HashAlgorithm defines which hashing algorithm to use when generating a TOTP.
// The default for most apps is SHA-1.
type HashAlgorithm int

// Hashing algorithms. The default for most apps is SHA-1.
const (
	SHA1 HashAlgorithm = iota
	SHA256
	SHA512
)

// TODO: Replace with stringer.
var algToString = map[HashAlgorithm]string{ //nolint:gochecknoglobals
	SHA1:   "SHA1",
	SHA256: "SHA256",
	SHA512: "SHA512",
}

// TOTP is used to generate and verify Timed One Time Password tokens.
type TOTP struct {
	secret      []byte
	algorithm   HashAlgorithm
	issuer      string
	accountName string
	digits      uint8
	period      time.Duration
}

// Params can configure optional parameters for new TOTP generation.
type Params struct{}

// New creates a new TOTP generator/verifier with a randomly generated secret.
func New(_ Params) (*TOTP, error) { return nil, errUnimplemented }

// UnmarshalBytes loads a proto-encoded TOTP message. This should be used when
// loading TOTP secrets from storage.
func UnmarshalBytes(_ []byte) (*TOTP, error) { return nil, errUnimplemented }

// FromString loads a URI-encoded TOTP message. This should be used when loading
// TOTP secrets from a QR Code.
func FromString(_ string) (*TOTP, error) { return nil, errUnimplemented }

// MarshalBytes serializes the TOTP object in a protobuf format. This should be
// used for storing a TOTP secret.
func (t *TOTP) MarshalBytes() ([]byte, error) { return nil, errUnimplemented }

func encodeURIQuery(values map[string]string) string {
	params := make([]string, 0, len(values))
	for k, v := range values {
		params = append(params, url.PathEscape(k)+"="+url.PathEscape(v))
	}

	sort.Strings(params)

	return strings.Join(params, "&")
}

// String serializes the TOTP object in a URI format that is compatible with
// Google Authenticator.
func (t *TOTP) String() string {
	uri := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/" + t.issuer + ":" + t.accountName,
		RawQuery: encodeURIQuery(map[string]string{
			"secret":    base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.secret),
			"issuer":    t.issuer,
			"period":    strconv.Itoa(int(t.period.Seconds())),
			"algorithm": algToString[t.algorithm],
			"digits":    strconv.Itoa(int(t.digits)),
		}),
	}

	return uri.String()
}

func chunkString(str string) []string {
	count := math.Ceil(float64(len(str)) / secretChunkSize)
	chunks := make([]string, int(count))

	for i := range chunks {
		start := i * secretChunkSize
		end := start + secretChunkSize

		if end > len(str) {
			end = len(str)
		}

		chunks[i] = str[start:end]
	}

	return chunks
}

// Secret outputs the secret in a base32-encoded format. This is useful for
// copy/paste into authenticator apps when a QR code is not available. It is
// highly recommended to use SHA-1 with this as many apps will default to SHA-1.
func (t *TOTP) Secret() string {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.secret)

	return strings.Join(chunkString(encoded), "-")
}

// Generate generates a new TOTP.
func (t *TOTP) Generate() (string, error) { return "", errUnimplemented }

// Verify verifies a given TOTP.
func (t *TOTP) Verify(_ string) error { return errUnimplemented }
