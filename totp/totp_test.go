package totp

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestSecret(t *testing.T) {
	for _, test := range []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "10-character secret",
			in:   []byte("abcdefghij"),
			want: "MFRG-GZDF-MZTW-Q2LK",
		},
		{
			name: "Short secret",
			in:   []byte("0"),
			want: "GA",
		},
		{
			name: "Long, odd secret",
			in:   []byte("abcdefghijklmnopqrstuvwxyz"),
			want: "MFRG-GZDF-MZTW-Q2LK-NNWG-23TP-OBYX-E43U-OV3H-O6DZ-PI",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			otp := &TOTP{secret: test.in}
			if got := otp.Secret(); got != test.want {
				t.Errorf("Secret(%x) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestString(t *testing.T) {
	for _, test := range []struct {
		name string
		in   *TOTP
		want string
	}{
		{
			name: "all features",
			in: &TOTP{
				issuer:      "go pass lib",
				accountName: "user@example.com",
				secret:      []byte("0123456789"),
				digits:      6,
				period:      30 * time.Second,
				algorithm:   SHA1,
			},
			want: "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=SHA1&digits=6&issuer=go%20pass%20lib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
		},
		{
			name: "SHA256",
			in: &TOTP{
				issuer:      "go pass lib",
				accountName: "user@example.com",
				secret:      []byte("0123456789"),
				digits:      6,
				period:      30 * time.Second,
				algorithm:   SHA256,
			},
			want: "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=SHA256&digits=6&issuer=go%20pass%20lib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
		},
		{
			name: "SHA256",
			in: &TOTP{
				issuer:      "go pass lib",
				accountName: "user@example.com",
				secret:      []byte("0123456789"),
				digits:      6,
				period:      30 * time.Second,
				algorithm:   SHA512,
			},
			want: "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=SHA512&digits=6&issuer=go%20pass%20lib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.in.String(); got != test.want {
				t.Errorf("String() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFromString(t *testing.T) { //nolint:funlen
	for _, test := range []struct {
		name    string
		in      string
		want    *TOTP
		wantErr error
	}{
		{
			name: "full featured with SHA256",
			in:   "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=SHA256&digits=6&issuer=go%20pass%20lib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
			want: &TOTP{
				issuer:      "go pass lib",
				accountName: "user@example.com",
				secret:      []byte("0123456789"),
				digits:      6,
				period:      30 * time.Second,
				algorithm:   SHA256,
				lookback:    1,
			},
			wantErr: nil,
		},
		{
			name:    "bad uri",
			in:      "\t",
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name:    "No split in path",
			in:      "otpauth://totp/go%20pass%20lib/user@example.com?algorithm=SHA256&digits=6&issuer=go%20pass%20lib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name:    "missing digits",
			in:      "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=SHA256&issuer=go%20pass%20lib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name:    "digits out of range",
			in:      "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=SHA256&digits=-6&issuer=go%20pass%20lib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name:    "missing period",
			in:      "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=SHA256&digits=6&issuer=go%20pass%20lib&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name:    "period out of range",
			in:      "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=SHA256&digits=6&issuer=go%20pass%20lib&period=-30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name:    "missing algorithm",
			in:      "otpauth://totp/go%20pass%20lib:user@example.com?digits=6&issuer=go%20pass%20lib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name:    "bad algorithm",
			in:      "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=plaintext&digits=6&issuer=go%20pass%20lib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name:    "missing secret",
			in:      "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=SHA256&digits=6&issuer=go%20pass%20lib&period=30", //nolint:lll
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name:    "poorly encoded secret",
			in:      "otpauth://totp/go%20pass%20lib:user@example.com?algorithm=SHA256&digits=6&issuer=go%20pass%20lib&period=30&secret=1234567890abcdef", //nolint:lll
			want:    nil,
			wantErr: ErrInvalid,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := FromString(test.in)
			if !errors.Is(err, test.wantErr) {
				t.Errorf("FromString(%q) err = %s, want %s", test.in, err, test.wantErr)
			}
			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(TOTP{})); diff != "" {
				t.Errorf("FromString() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHOTP(t *testing.T) {
	for i, want := range []string{ //nolint:varnamelen
		"755224",
		"287082",
		"359152",
		"969429",
		"338314",
		"254676",
		"287922",
		"162583",
		"399871",
		"520489",
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			otp := &TOTP{
				secret:    []byte("12345678901234567890"),
				digits:    6,
				algorithm: SHA1,
			}
			got, err := otp.hotp(uint64(i))
			if err != nil {
				t.Errorf("hotp(%d) failed: %s", i, err)
			}
			if got != want {
				t.Errorf("hotp(%d) = %s, want %s", i, got, want)
			}
		})
	}
}

func TestTOTP(t *testing.T) {
	for _, test := range []struct {
		unixTime  int
		algorithm HashAlgorithm
		want      string
	}{
		{unixTime: 59, want: "94287082", algorithm: SHA1},
		{unixTime: 59, want: "46119246", algorithm: SHA256},
		{unixTime: 59, want: "90693936", algorithm: SHA512},
		{unixTime: 1111111109, want: "07081804", algorithm: SHA1},
		{unixTime: 1111111109, want: "68084774", algorithm: SHA256},
		{unixTime: 1111111109, want: "25091201", algorithm: SHA512},
		{unixTime: 1111111111, want: "14050471", algorithm: SHA1},
		{unixTime: 1111111111, want: "67062674", algorithm: SHA256},
		{unixTime: 1111111111, want: "99943326", algorithm: SHA512},
		{unixTime: 1234567890, want: "89005924", algorithm: SHA1},
		{unixTime: 1234567890, want: "91819424", algorithm: SHA256},
		{unixTime: 1234567890, want: "93441116", algorithm: SHA512},
		{unixTime: 2000000000, want: "69279037", algorithm: SHA1},
		{unixTime: 2000000000, want: "90698825", algorithm: SHA256},
		{unixTime: 2000000000, want: "38618901", algorithm: SHA512},
		{unixTime: 20000000000, want: "65353130", algorithm: SHA1},
		{unixTime: 20000000000, want: "77737706", algorithm: SHA256},
		{unixTime: 20000000000, want: "47863826", algorithm: SHA512},
	} {
		t.Run(fmt.Sprintf("%d-%v", test.unixTime, test.algorithm), func(t *testing.T) {
			var secret []byte
			switch test.algorithm {
			case SHA1:
				secret = []byte("12345678901234567890")
			case SHA256:
				secret = []byte("12345678901234567890123456789012")
			case SHA512:
				secret = []byte("1234567890123456789012345678901234567890123456789012345678901234")
			}
			otp := &TOTP{
				secret:    secret,
				algorithm: test.algorithm,
				digits:    8,
				period:    30 * time.Second,
				lookback:  1,
			}
			ts := time.Unix(int64(test.unixTime), 0)
			got, err := otp.totp(ts)
			if err != nil {
				t.Errorf("totp(%s) failed: %s", ts, err)
			}
			if got != test.want {
				t.Errorf("totp(%s) = %s, want %s", ts, got, test.want)
			}
		})
	}
}
