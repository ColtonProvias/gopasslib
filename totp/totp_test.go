package totp

import "testing"

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
