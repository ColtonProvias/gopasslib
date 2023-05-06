// Package totp is used to generate and verify Timed One-Time Passwords.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	pb "github.com/ColtonProvias/gopasslib/proto"
	"google.golang.org/protobuf/proto"
)

const (
	secretChunkSize     = 4
	defaultSecretLength = 20
	defaultDigits       = 6
	defaultPeriod       = 30 * time.Second
	defaultLookback     = 1
)

// ErrInvalid is returned when a parameter fails validation.
var ErrInvalid = errors.New("invalid")

// ErrTokenFailed is returned when a TOTP fails verification.
var ErrTokenFailed = errors.New("could not verify token")

// HashAlgorithm defines which hashing algorithm to use when generating a TOTP.
// The default for most apps is SHA-1.
type HashAlgorithm int

// Hashing algorithms. The default for most apps is SHA-1.
const (
	SHA1 HashAlgorithm = iota
	SHA256
	SHA512
)

var algToString = map[HashAlgorithm]string{ //nolint:gochecknoglobals
	SHA1:   "SHA1",
	SHA256: "SHA256",
	SHA512: "SHA512",
}

var stringToAlg = map[string]HashAlgorithm{ //nolint:gochecknoglobals
	"SHA1":   SHA1,
	"SHA256": SHA256,
	"SHA512": SHA512,
}

var algToProto = map[HashAlgorithm]pb.TOTP_HashAlgorithm{ //nolint:gochecknoglobals
	SHA1:   pb.TOTP_HASH_ALGORITHM_SHA_1,
	SHA256: pb.TOTP_HASH_ALGORITHM_SHA_256,
	SHA512: pb.TOTP_HASH_ALGORITHM_SHA_512,
}

var protoToAlg = map[pb.TOTP_HashAlgorithm]HashAlgorithm{ //nolint:gochecknoglobals
	pb.TOTP_HASH_ALGORITHM_SHA_1:   SHA1,
	pb.TOTP_HASH_ALGORITHM_SHA_256: SHA256,
	pb.TOTP_HASH_ALGORITHM_SHA_512: SHA512,
}

var algToHash = map[HashAlgorithm]func() hash.Hash{ //nolint:gochecknoglobals
	SHA1:   sha1.New,
	SHA256: sha256.New,
	SHA512: sha512.New,
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
type Params struct {
	Issuer        string
	AccountName   string
	HashAlgorithm HashAlgorithm
	SecretLength  uint
	Digits        uint8
	Period        time.Duration
	Lookback      uint
}

func (p *Params) applyDefaults() {
	if p.SecretLength == 0 {
		p.SecretLength = defaultSecretLength
	}

	if p.Digits == 0 {
		p.Digits = defaultDigits
	}

	if p.Period == 0 {
		p.Period = defaultPeriod
	}

	if p.Lookback == 0 {
		p.Lookback = defaultLookback
	}
}

func (p *Params) validate() error {
	var errs []error

	if p.Digits < 6 || p.Digits > 10 {
		errs = append(errs, fmt.Errorf("digits must be between 6 and 10 inclusive: %w", ErrInvalid))
	}

	if p.Issuer == "" {
		errs = append(errs, fmt.Errorf("issuer must not be empty: %w", ErrInvalid))
	}

	if p.AccountName == "" {
		errs = append(errs, fmt.Errorf("account name must not be empty: %w", ErrInvalid))
	}

	return errors.Join(errs...)
}

// New creates a new TOTP generator/verifier with a randomly generated secret.
func New(params Params) (*TOTP, error) {
	params.applyDefaults()

	if err := params.validate(); err != nil {
		return nil, err
	}

	secret := make([]byte, params.SecretLength)

	_, err := io.ReadFull(rand.Reader, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	return &TOTP{
		algorithm:   params.HashAlgorithm,
		secret:      secret,
		issuer:      params.Issuer,
		accountName: params.AccountName,
		digits:      params.Digits,
		period:      params.Period,
		lookback:    params.Lookback,
	}, nil
}

func validateProto(msg *pb.TOTP) error {
	var errs []error

	if _, ok := protoToAlg[msg.HashAlgorithm]; !ok {
		errs = append(errs, fmt.Errorf("unknown hash algorithm: %w", ErrInvalid))
	}

	if len(msg.Secret) == 0 {
		errs = append(errs, fmt.Errorf("secret must not be empty: %w", ErrInvalid))
	}

	if msg.Issuer == "" {
		errs = append(errs, fmt.Errorf("issuer must not be empty: %w", ErrInvalid))
	}

	if msg.AccountName == "" {
		errs = append(errs, fmt.Errorf("account name must not be empty: %w", ErrInvalid))
	}

	if msg.PeriodSeconds == 0 {
		errs = append(errs, fmt.Errorf("period must be greater than 0: %w", ErrInvalid))
	}

	if msg.Digits < 6 || msg.Digits > 10 {
		errs = append(errs, fmt.Errorf("digits must be between 6 to 10 inclusive: %w", ErrInvalid))
	}

	return errors.Join(errs...)
}

// Unmarshal loads a proto-encoded TOTP message. This should be used when
// loading TOTP secrets from storage.
func Unmarshal(encoded []byte) (*TOTP, error) {
	msg := &pb.TOTP{}

	if err := proto.Unmarshal(encoded, msg); err != nil {
		return nil, fmt.Errorf("could not unmarshal TOTP: %w", err)
	}

	if err := validateProto(msg); err != nil {
		return nil, err
	}

	return &TOTP{
		secret:      msg.Secret,
		algorithm:   protoToAlg[msg.HashAlgorithm],
		issuer:      msg.Issuer,
		accountName: msg.AccountName,
		period:      time.Duration(msg.PeriodSeconds) * time.Second,
		lookback:    uint(msg.LookbackPeriods),
		digits:      uint8(msg.Digits),
	}, nil
}

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
	if err != nil || digits < 6 || digits > 10 {
		return nil, fmt.Errorf("digits must be a number between 6 and 10: %w", ErrInvalid)
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

// Marshal serializes the TOTP object in a protobuf format. This should be used
// for storing a TOTP secret.
func (t *TOTP) Marshal() ([]byte, error) {
	msg := &pb.TOTP{
		Secret:          t.secret,
		HashAlgorithm:   algToProto[t.algorithm],
		Issuer:          t.issuer,
		AccountName:     t.accountName,
		Digits:          uint32(t.digits),
		PeriodSeconds:   uint32(t.period.Seconds()),
		LookbackPeriods: uint32(t.lookback),
	}

	encoded, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal: %w", err)
	}

	return encoded, nil
}

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

func (t *TOTP) hotp(counter uint64) (string, error) {
	hf := algToHash[t.algorithm]
	h := hmac.New(hf, t.secret)

	if err := binary.Write(h, binary.BigEndian, counter); err != nil {
		return "", fmt.Errorf("failed to write counter: %w", err)
	}

	hs := h.Sum(nil)
	offset := hs[len(hs)-1] & 0xf                                      //nolint:gomnd
	sbits := binary.BigEndian.Uint32(hs[offset:offset+4]) & 0x7fffffff //nolint:gomnd
	format := fmt.Sprintf("%%0%dd", t.digits)

	return fmt.Sprintf(format, sbits%uint32(math.Pow10(int(t.digits)))), nil
}

func (t *TOTP) totp(ts time.Time) (string, error) {
	return t.hotp(uint64(ts.Unix() / int64(t.period.Seconds())))
}

// Generate generates a new TOTP.
func (t *TOTP) Generate() (string, error) {
	return t.totp(time.Now())
}

func (t *TOTP) verify(cur time.Time, code string) error {
	if len(code) != int(t.digits) {
		return ErrTokenFailed
	}

	for i := 0; i <= int(t.lookback); i++ {
		generated, err := t.totp(cur)
		if err != nil {
			return err
		}

		if generated == code {
			return nil
		}

		cur = cur.Add(-t.period)
	}

	return ErrTokenFailed
}

// Verify verifies a given TOTP.
func (t *TOTP) Verify(code string) error {
	return t.verify(time.Now(), code)
}
