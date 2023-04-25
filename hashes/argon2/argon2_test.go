package argon2_test

import (
	"errors"
	"testing"

	"github.com/ColtonProvias/gopasslib/hashes/argon2"
	pb "github.com/ColtonProvias/gopasslib/proto"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestProtoSerialization(t *testing.T) {
	for _, test := range []struct {
		name string
		msg  *pb.PasswordArgon2
	}{
		{
			name: "variant id",
			msg: &pb.PasswordArgon2{
				Hash:      []byte("abc123"),
				Salt:      []byte("1234"),
				Threads:   1,
				MemoryKib: 2,
				Time:      3,
				Variant:   pb.PasswordArgon2_VARIANT_ID,
				Version:   0x13,
			},
		},
		{
			name: "variant i",
			msg: &pb.PasswordArgon2{
				Hash:      []byte("abc123"),
				Salt:      []byte("1234"),
				Threads:   1,
				MemoryKib: 2,
				Time:      3,
				Variant:   pb.PasswordArgon2_VARIANT_I,
				Version:   0x13,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, err := argon2.New(argon2.Params{})
			if err != nil {
				t.Fatalf("argon2.New() failed: %s", err)
			}

			loaded, err := h.FromMessage(test.msg)
			if err != nil {
				t.Fatalf("FromMessage() failed: %s", err)
			}

			got := loaded.ProtoMessage()
			if diff := cmp.Diff(test.msg, got, protocmp.Transform()); diff != "" {
				t.Errorf("ProtoMessage() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProtoValidation(t *testing.T) { //nolint:funlen
	for _, test := range []struct {
		name    string
		in      *pb.PasswordArgon2
		wantErr error
	}{
		{
			name: "default",
			in: &pb.PasswordArgon2{
				Variant:   pb.PasswordArgon2_VARIANT_ID,
				MemoryKib: 64 * 1024,
				Time:      1,
				Threads:   4,
				Hash:      []byte("0123456789"),
				Salt:      []byte("1234"),
				Version:   0x13,
			},
			wantErr: nil,
		},
		{
			name: "bad variant",
			in: &pb.PasswordArgon2{
				Variant:   pb.PasswordArgon2_VARIANT_UNDEFINED,
				MemoryKib: 64 * 1024,
				Time:      1,
				Threads:   4,
				Hash:      []byte("0123456789"),
				Salt:      []byte("1234"),
				Version:   0x13,
			},
			wantErr: argon2.ErrInvalid,
		},
		{
			name: "bad memory",
			in: &pb.PasswordArgon2{
				Variant:   pb.PasswordArgon2_VARIANT_ID,
				MemoryKib: 0,
				Time:      1,
				Threads:   4,
				Hash:      []byte("0123456789"),
				Salt:      []byte("1234"),
				Version:   0x13,
			},
			wantErr: argon2.ErrInvalid,
		},
		{
			name: "bad threads",
			in: &pb.PasswordArgon2{
				Variant:   pb.PasswordArgon2_VARIANT_ID,
				MemoryKib: 64 * 1024,
				Time:      1,
				Threads:   0,
				Hash:      []byte("0123456789"),
				Salt:      []byte("1234"),
				Version:   0x13,
			},
			wantErr: argon2.ErrInvalid,
		},
		{
			name: "bad time",
			in: &pb.PasswordArgon2{
				Variant:   pb.PasswordArgon2_VARIANT_ID,
				MemoryKib: 64 * 1024,
				Time:      0,
				Threads:   4,
				Hash:      []byte("0123456789"),
				Salt:      []byte("1234"),
				Version:   0x13,
			},
			wantErr: argon2.ErrInvalid,
		},
		{
			name: "bad hash",
			in: &pb.PasswordArgon2{
				Variant:   pb.PasswordArgon2_VARIANT_ID,
				MemoryKib: 64 * 1024,
				Time:      1,
				Threads:   4,
				Hash:      nil,
				Salt:      []byte("1234"),
				Version:   0x13,
			},
			wantErr: argon2.ErrInvalid,
		},
		{
			name: "bad salt",
			in: &pb.PasswordArgon2{
				Variant:   pb.PasswordArgon2_VARIANT_ID,
				MemoryKib: 64 * 1024,
				Time:      1,
				Threads:   4,
				Hash:      []byte("0123456789"),
				Salt:      nil,
				Version:   0x13,
			},
			wantErr: argon2.ErrInvalid,
		},
		{
			name: "bad version",
			in: &pb.PasswordArgon2{
				Variant:   pb.PasswordArgon2_VARIANT_ID,
				MemoryKib: 64 * 1024,
				Time:      1,
				Threads:   4,
				Hash:      []byte("0123456789"),
				Salt:      []byte("1234"),
				Version:   0x12,
			},
			wantErr: argon2.ErrInvalid,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, err := argon2.New(argon2.Params{})
			if err != nil {
				t.Fatalf("argon2.New() failed: %s", err)
			}
			_, err = h.FromMessage(test.in)
			if !errors.Is(err, test.wantErr) {
				t.Errorf("h.FromMessage() err = %s, want %s", err, test.wantErr)
			}
		})
	}
}
