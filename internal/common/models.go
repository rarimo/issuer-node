package common

import "github.com/pkg/errors"

var (
	ErrCredentialIsNil        = errors.New("credential is nil")
	ErrInvalidProofType       = errors.New("invalid proof type")
	ErrInvalidSignatureLength = errors.New("invalid signature length")
)

type ClaimSchemaType string

func (c ClaimSchemaType) String() string {
	return string(c)
}
