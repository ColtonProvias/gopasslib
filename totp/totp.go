// Package totp is used to generate and verify Timed One-Time Passwords.
package totp

import "errors"

var errUnimplemented = errors.New("unimplemented")

// TOTP is used to generate and verify Timed One Time Password tokens.
type TOTP struct{}

// Params can configure optional parameters for new TOTP generation.
type Params struct{}

// New creates a new TOTP generator/verifier with a randomly generated secret.
func New(_ Params) (*TOTP, error) { return nil, errUnimplemented }

// UnmarshalBytes loads a proto-encoded TOTP message. This should be used when
// loading TOTP secrets from storage.
func UnmarshalBytes(_ []byte) (*TOTP, error) { return nil, errUnimplemented }

// UnmarshalString loads a URI-encoded TOTP message. This should be used when
// loading TOTP secrets from a QR Code.
func UnmarshalString(_ string) (*TOTP, error) { return nil, errUnimplemented }

// MarshalBytes serializes the TOTP object in a protobuf format. This should be
// used for storing a TOTP secret.
func (t *TOTP) MarshalBytes() ([]byte, error) { return nil, errUnimplemented }

// MarshalString serializes the TOTP object in a URI format that is compatible
// with Google Authenticator.
func (t *TOTP) MarshalString() string { return "" }

// Secret outputs the secret in a base32-encoded format. This is useful for
// copy/paste into authenticator apps when a QR code is not available. You must
// use SHA-1 for this.
func (t *TOTP) Secret() string { return "" }

// Generate generates a new TOTP.
func (t *TOTP) Generate() (string, error) { return "", errUnimplemented }

// Verify verifies a given TOTP.
func (t *TOTP) Verify(_ string) error { return errUnimplemented }
