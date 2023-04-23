// Package argon2 implements the interface for the argon2 password hashing
// algorithm.
package argon2

import (
	"context"
	"errors"

	pb "github.com/ColtonProvias/gopasslib/proto"
	"google.golang.org/protobuf/proto"
)

// Temporary error sentinel for use during development.
// TODO: Remove once this module has been completed.
var errUnimplemented = errors.New("unimplemented")

// Params to be used during Argon2 hashing.
type Params struct{}

func (p *Params) validate() error {
	return errUnimplemented
}

// Hasher is used to work with Argon2 passwords.
type Hasher struct{}

// HashedPassword contains a hashed Argon2 password.
type HashedPassword struct{}

// New constructs a new Argon2 hasher instance.
func New(p Params) (*Hasher, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	return nil, errUnimplemented
}

// Hash runs the Argon2 algorithm on the provided password.
func (h *Hasher) Hash(_ context.Context, _ []byte) (*HashedPassword, error) {
	return nil, errUnimplemented
}

// FromMessage converts the Argon2 proto message into a HashedPassword instance.
func (h *Hasher) FromMessage(_ proto.Message) (*HashedPassword, error) {
	return nil, errUnimplemented
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
	return nil
}

// String dumps the hashed password to a PHC formatted string.
func (hp *HashedPassword) String() string {
	return ""
}
