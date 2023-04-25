package totp

import (
	"testing"
	"time"
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
				issuer:      "gopasslib",
				accountName: "user@example.com",
				secret:      []byte("0123456789"),
				digits:      6,
				period:      30 * time.Second,
				algorithm:   SHA1,
			},
			want: "otpauth://totp/gopasslib:user@example.com?algorithm=SHA1&digits=6&issuer=gopasslib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
		},
		{
			name: "SHA256",
			in: &TOTP{
				issuer:      "gopasslib",
				accountName: "user@example.com",
				secret:      []byte("0123456789"),
				digits:      6,
				period:      30 * time.Second,
				algorithm:   SHA256,
			},
			want: "otpauth://totp/gopasslib:user@example.com?algorithm=SHA256&digits=6&issuer=gopasslib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
		},
		{
			name: "SHA256",
			in: &TOTP{
				issuer:      "gopasslib",
				accountName: "user@example.com",
				secret:      []byte("0123456789"),
				digits:      6,
				period:      30 * time.Second,
				algorithm:   SHA512,
			},
			want: "otpauth://totp/gopasslib:user@example.com?algorithm=SHA512&digits=6&issuer=gopasslib&period=30&secret=GAYTEMZUGU3DOOBZ", //nolint:lll
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.in.String(); got != test.want {
				t.Errorf("String() = %q, want %q", got, test.want)
			}
		})
	}
}
