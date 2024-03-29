package totp

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	pb "github.com/ColtonProvias/gopasslib/proto"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
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

func TestVerify(t *testing.T) {
	otp := &TOTP{
		secret:    []byte("12345678901234567890123456789012"),
		algorithm: SHA256,
		digits:    8,
		period:    30 * time.Second,
		lookback:  1,
	}
	now := time.Unix(1234567890, 0)

	for _, test := range []struct {
		name    string
		time    time.Time
		token   string
		wantErr error
	}{
		{
			name:    "short token",
			time:    now,
			token:   "123456",
			wantErr: ErrTokenFailed,
		},
		{
			name:    "good token",
			time:    now,
			token:   "91819424",
			wantErr: nil,
		},
		{
			name:    "1 period into the future",
			time:    now.Add(30 * time.Second),
			token:   "91819424",
			wantErr: nil,
		},
		{
			name:    "2 periods into the future",
			time:    now.Add(60 * time.Second),
			token:   "91819424",
			wantErr: ErrTokenFailed,
		},
		{
			name:    "1 period into the past",
			time:    now.Add(-30 * time.Second),
			token:   "91819424",
			wantErr: ErrTokenFailed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := otp.verify(test.time, test.token); !errors.Is(err, test.wantErr) {
				t.Errorf("verify() err = %s, want %s", err, test.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	for _, test := range []struct {
		name    string
		params  Params
		wantErr error
	}{
		{
			name: "good",
			params: Params{
				Issuer:      "gopasslib",
				AccountName: "user@example.com",
			},
			wantErr: nil,
		},
		{
			name: "bad digits",
			params: Params{
				Digits:      5,
				Issuer:      "gopasslib",
				AccountName: "user@example.com",
			},
			wantErr: ErrInvalid,
		},
		{
			name: "missing issuer",
			params: Params{
				AccountName: "user@example.com",
			},
			wantErr: ErrInvalid,
		},
		{
			name: "missing account",
			params: Params{
				Issuer: "gopasslib",
			},
			wantErr: ErrInvalid,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.params); !errors.Is(err, test.wantErr) {
				t.Errorf("New() err = %s, want %s", err, test.wantErr)
			}
		})
	}
}

func TestNewToVerify(t *testing.T) {
	otp, err := New(Params{
		Issuer:      "gopasslib",
		AccountName: "user@example.com",
	})
	if err != nil {
		t.Fatalf("New() failed: %s", err)
	}

	token, err := otp.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %s", err)
	}

	if err := otp.Verify(token); err != nil {
		t.Errorf("Verify() failed: %s", err)
	}
}

func TestMarshal(t *testing.T) {
	want := &pb.TOTP{
		AccountName:     "user@example.com",
		Digits:          6,
		HashAlgorithm:   pb.TOTP_HASH_ALGORITHM_SHA_512,
		Issuer:          "gopasslib",
		LookbackPeriods: 1,
		PeriodSeconds:   30,
		Secret:          []byte("1234"),
	}
	otp := &TOTP{
		secret:      []byte("1234"),
		algorithm:   SHA512,
		issuer:      "gopasslib",
		accountName: "user@example.com",
		digits:      6,
		period:      30 * time.Second,
		lookback:    1,
	}

	encoded, err := otp.Marshal()
	if err != nil {
		t.Fatalf("Marshal() failed: %s", err)
	}

	got := &pb.TOTP{}

	if err := proto.Unmarshal(encoded, got); err != nil {
		t.Fatalf("proto.Unmarshal() failed: %s", err)
	}

	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("Marshal() mismatch (-want +got):\n%s", diff)
	}
}

func TestUnmarshal(t *testing.T) { //nolint:funlen
	for _, test := range []struct {
		name    string
		in      proto.Message
		want    *TOTP
		wantErr error
	}{
		{
			name: "good",
			in: &pb.TOTP{
				Secret:          []byte("1234567890"),
				Issuer:          "gopasslib",
				AccountName:     "alice@bob.eve",
				PeriodSeconds:   30,
				Digits:          8,
				LookbackPeriods: 1,
				HashAlgorithm:   pb.TOTP_HASH_ALGORITHM_SHA_256,
			},
			want: &TOTP{
				secret:      []byte("1234567890"),
				issuer:      "gopasslib",
				accountName: "alice@bob.eve",
				period:      30 * time.Second,
				digits:      8,
				lookback:    1,
				algorithm:   SHA256,
			},
			wantErr: nil,
		},
		{
			name: "missing algorithm",
			in: &pb.TOTP{
				Secret:          []byte("1234567890"),
				Issuer:          "gopasslib",
				AccountName:     "alice@bob.eve",
				PeriodSeconds:   30,
				Digits:          8,
				LookbackPeriods: 1,
			},
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name: "missing secret",
			in: &pb.TOTP{
				Issuer:          "gopasslib",
				AccountName:     "alice@bob.eve",
				PeriodSeconds:   30,
				Digits:          8,
				LookbackPeriods: 1,
				HashAlgorithm:   pb.TOTP_HASH_ALGORITHM_SHA_512,
			},
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name: "missing issuer",
			in: &pb.TOTP{
				Secret:          []byte("1234567890"),
				AccountName:     "alice@bob.eve",
				PeriodSeconds:   30,
				Digits:          8,
				LookbackPeriods: 1,
				HashAlgorithm:   pb.TOTP_HASH_ALGORITHM_SHA_512,
			},
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name: "missing account name",
			in: &pb.TOTP{
				Secret:          []byte("1234567890"),
				Issuer:          "gopasslib",
				PeriodSeconds:   30,
				Digits:          8,
				LookbackPeriods: 1,
				HashAlgorithm:   pb.TOTP_HASH_ALGORITHM_SHA_512,
			},
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name: "missing periods",
			in: &pb.TOTP{
				Secret:          []byte("1234567890"),
				Issuer:          "gopasslib",
				AccountName:     "alice@bob.eve",
				Digits:          8,
				LookbackPeriods: 1,
				HashAlgorithm:   pb.TOTP_HASH_ALGORITHM_SHA_512,
			},
			want:    nil,
			wantErr: ErrInvalid,
		},
		{
			name: "mmissing digits",
			in: &pb.TOTP{
				Secret:          []byte("1234567890"),
				Issuer:          "gopasslib",
				AccountName:     "alice@bob.eve",
				PeriodSeconds:   30,
				LookbackPeriods: 1,
				HashAlgorithm:   pb.TOTP_HASH_ALGORITHM_SHA_512,
			},
			want:    nil,
			wantErr: ErrInvalid,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := proto.Marshal(test.in)
			if err != nil {
				t.Fatalf("proto.Marshal() failed: %s", err)
			}
			got, gotErr := Unmarshal(encoded)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf("Unmarshal() err = %s, want %s", gotErr, test.wantErr)
			}
			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(TOTP{})); diff != "" {
				t.Errorf("Unmarshal() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
