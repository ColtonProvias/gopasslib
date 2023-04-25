package totp

import (
	"errors"
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
