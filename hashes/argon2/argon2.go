// Package argon2 implements the interface for the argon2 password hashing
// algorithm.
package argon2

import (
	"context"
	"errors"
	"fmt"

	pb "github.com/ColtonProvias/gopasslib/proto"
)

// Temporary error sentinel for use during development.
// TODO: Remove once this module has been completed.
var errUnimplemented = errors.New("unimplemented")

// ErrInvalid denotes an invalid serialized hash.
var ErrInvalid = errors.New("invalid")

// Variant defines the argon2 variant to use. The default should be VariantID.
type Variant int

// Argon2 variants. ID is the recommendation if uncertain of which to use.
const (
	variantUndefined Variant = iota
	VariantI
	VariantID
)

const version = 0x13

const (
	defaultVariant    = VariantID
	defaultHashLength = 32
	defaultSaltLength = 16
	defaultTime       = 1
	defaultMemory     = 64 * 1024
	defaultThreads    = 4
)

func variantToProto(v Variant) pb.PasswordArgon2_Variant {
	switch v {
	case VariantI:
		return pb.PasswordArgon2_VARIANT_I
	case VariantID:
		return pb.PasswordArgon2_VARIANT_ID
	default:
		return pb.PasswordArgon2_VARIANT_UNDEFINED
	}
}

func protoToVariant(enum pb.PasswordArgon2_Variant) Variant {
	switch enum {
	case pb.PasswordArgon2_VARIANT_I:
		return VariantI
	case pb.PasswordArgon2_VARIANT_ID:
		return VariantID
	default:
		return variantUndefined
	}
}

// Params to be used during Argon2 hashing.
type Params struct {
	HashLength uint
	SaltLength uint
	Time       uint
	MemoryKiB  uint
	Threads    uint
	Variant    Variant
}

func (p *Params) applyDefaults() {
	if p.Variant == variantUndefined {
		p.Variant = defaultVariant
	}

	if p.HashLength == 0 {
		p.HashLength = defaultHashLength
	}

	if p.SaltLength == 0 {
		p.SaltLength = defaultSaltLength
	}

	if p.Time == 0 {
		p.Time = defaultTime
	}

	if p.MemoryKiB == 0 {
		p.MemoryKiB = defaultMemory
	}

	if p.Threads == 0 {
		p.Threads = defaultThreads
	}
}

// Hasher is used to work with Argon2 passwords.
type Hasher struct {
	hashLength uint
	saltLength uint
	time       uint
	memoryKiB  uint
	threads    uint
	variant    Variant
}

// HashedPassword contains a hashed Argon2 password.
type HashedPassword struct {
	hasher  *Hasher
	variant Variant
	hash    []byte
	salt    []byte
	time    uint32
	memory  uint32
	threads uint32
}

// New constructs a new Argon2 hasher instance.
func New(params Params) (*Hasher, error) {
	params.applyDefaults()

	return &Hasher{
		hashLength: params.HashLength,
		saltLength: params.SaltLength,
		time:       params.Time,
		threads:    params.Threads,
		memoryKiB:  params.MemoryKiB,
		variant:    params.Variant,
	}, nil
}

// Hash runs the Argon2 algorithm on the provided password.
func (h *Hasher) Hash(_ context.Context, _ []byte) (*HashedPassword, error) {
	return nil, errUnimplemented
}

func (h *Hasher) validateMessage(msg *pb.PasswordArgon2) error {
	var errs []error

	if msg.Variant == pb.PasswordArgon2_VARIANT_UNDEFINED {
		errs = append(errs, fmt.Errorf("unsupported variant: %w", ErrInvalid))
	}

	if len(msg.Hash) == 0 {
		errs = append(errs, fmt.Errorf("empty hash: %w", ErrInvalid))
	}

	if len(msg.Salt) == 0 {
		errs = append(errs, fmt.Errorf("empty salt: %w", ErrInvalid))
	}

	if msg.Threads == 0 {
		errs = append(errs, fmt.Errorf("threads must be greater than 0: %w", ErrInvalid))
	}

	if msg.Time == 0 {
		errs = append(errs, fmt.Errorf("time must be greater than 0: %w", ErrInvalid))
	}

	if msg.MemoryKib == 0 {
		errs = append(errs, fmt.Errorf("memory must be greater than 0: %w", ErrInvalid))
	}

	if msg.Version != version {
		errs = append(errs, fmt.Errorf("only version 0x13 is supported, got 0x%x: %w", msg.Version, ErrInvalid))
	}

	return errors.Join(errs...)
}

// FromMessage converts the Argon2 proto message into a HashedPassword instance.
func (h *Hasher) FromMessage(msg *pb.PasswordArgon2) (*HashedPassword, error) {
	if err := h.validateMessage(msg); err != nil {
		return nil, fmt.Errorf("invalid proto message: %w", err)
	}

	hashed := &HashedPassword{
		hasher:  h,
		variant: protoToVariant(msg.Variant),
		hash:    msg.Hash,
		salt:    msg.Salt,
		memory:  msg.MemoryKib,
		time:    msg.Time,
		threads: msg.Threads,
	}

	return hashed, nil
}

// FromString converts an Argon2 password from PHC format into a HashedPassword
// instance.
func (h *Hasher) FromString(_ string) (*HashedPassword, error) {
	return nil, errUnimplemented
}

// Verify compares a given password against the stored password.
func (hp *HashedPassword) Verify(_ context.Context, _ []byte) error {
	return errUnimplemented
}

// ProtoMessage dumps the hashed password to a proto message for serialization.
func (hp *HashedPassword) ProtoMessage() *pb.PasswordArgon2 {
	return &pb.PasswordArgon2{
		Variant:   variantToProto(hp.variant),
		Version:   version,
		Hash:      hp.hash,
		Salt:      hp.salt,
		Time:      hp.time,
		Threads:   hp.threads,
		MemoryKib: hp.memory,
	}
}

// String dumps the hashed password to a PHC formatted string.
func (hp *HashedPassword) String() string {
	return ""
}
