// Package totp is used to generate and verify Timed One-Time Passwords.
package totp

import (
	"encoding/base32"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const secretChunkSize = 4

var errUnimplemented = errors.New("unimplemented")

// ErrInvalid is returned when a parameter fails validation.
var ErrInvalid = errors.New("invalid")

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

// TODO: Replace with stringer.
var stringToAlg = map[string]HashAlgorithm{ //nolint:gochecknoglobals
	"SHA1":   SHA1,
	"SHA256": SHA256,
	"SHA512": SHA512,
}

// TOTP is used to generate and verify Timed One Time Password tokens.
type TOTP struct {
	secret      []byte
	algorithm   HashAlgorithm
	issuer      string
	accountName string
	digits      uint8
	period      time.Duration
	lookback    uint
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
func FromString(uri string) (*TOTP, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TOTP from URI %q: %w: %w", uri, err, ErrInvalid)
	}

	pathParts := strings.Split(parsed.Path, ":")
	if len(pathParts) != 2 { //nolint:gomnd
		return nil, fmt.Errorf("invalid path %q: %w", parsed.Path, ErrInvalid)
	}

	issuer := strings.TrimPrefix(pathParts[0], "/")
	accountName := pathParts[1]
	query := parsed.Query()

	digits, err := strconv.Atoi(query.Get("digits"))
	if err != nil || digits < 6 || digits > 9 {
		return nil, fmt.Errorf("digits must be a number between 6 and 9: %w", ErrInvalid)
	}

	period, err := strconv.Atoi(query.Get("period"))
	if err != nil || period < 1 {
		return nil, fmt.Errorf("period must be a positive number: %w", ErrInvalid)
	}

	alg, ok := stringToAlg[query.Get("algorithm")]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm %q: %w", query.Get("algorithm"), ErrInvalid)
	}

	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(query.Get("secret"))
	if err != nil || len(secret) == 0 {
		return nil, fmt.Errorf("failed to decode secret: %w", ErrInvalid)
	}

	return &TOTP{
		issuer:      issuer,
		accountName: accountName,
		digits:      uint8(digits),
		period:      time.Duration(period) * time.Second,
		algorithm:   alg,
		secret:      secret,
		lookback:    1,
	}, nil
}

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
