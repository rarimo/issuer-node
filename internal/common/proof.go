package common

import (
	"encoding/hex"
	"encoding/json"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	mt "github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/pkg/errors"
)

// This is forked from github.com/iden3/go-schema-processor/verifiable/proofs.go
// Additional fields was added to the BJJSignatureProof2021 and Iden3SparseMerkleTreeProof structs

// BJJSignatureProof2021 JSON-LD BBJJSignatureProof
type BJJSignatureProof2021 struct {
	Type       verifiable.ProofType `json:"type"`
	IssuerData IssuerData           `json:"issuerData"`
	CoreClaim  string               `json:"coreClaim"`
	Signature  string               `json:"signature"`
}

// IssuerData is the data that is used to create a proof
type IssuerData struct {
	ID               string           `json:"id,omitempty"`
	UpdateURL        string           `json:"updateUrl,omitempty"`
	State            verifiable.State `json:"state,omitempty"`
	AuthCoreClaim    string           `json:"authCoreClaim,omitempty"`
	MTP              *mt.Proof        `json:"mtp,omitempty"`
	CredentialStatus interface{}      `json:"credentialStatus,omitempty"`
}

func (p *BJJSignatureProof2021) UnmarshalJSON(src []byte) error {
	var obj struct {
		Type       verifiable.ProofType `json:"type"`
		IssuerData json.RawMessage      `json:"issuerData"`
		CoreClaim  string               `json:"coreClaim"`
		Signature  string               `json:"signature"`
	}

	if err := json.Unmarshal(src, &obj); err != nil {
		return errors.Wrap(err, "failed to unmarshal proof")
	}

	if obj.Type != verifiable.BJJSignatureProofType {
		return ErrInvalidProofType
	}

	if err := json.Unmarshal(obj.IssuerData, &p.IssuerData); err != nil {
		return errors.Wrap(err, "failed to unmarshal issuer data")
	}

	if err := validateHexCoreClaim(obj.CoreClaim); err != nil {
		return errors.Wrap(err, "failed to validate core claim")
	}

	if err := validateCompSignature(obj.Signature); err != nil {
		return errors.Wrap(err, "failed to validate signature")
	}

	p.Type = obj.Type
	p.CoreClaim = obj.CoreClaim
	p.Signature = obj.Signature

	return nil
}

func validateHexCoreClaim(in string) error {
	var claim core.Claim

	if err := claim.FromHex(in); err != nil {
		return errors.Wrap(err, "failed to parse core claim from hex")
	}

	return nil
}

func validateCompSignature(in string) error {
	sigBytes, err := hex.DecodeString(in)
	if err != nil {
		return errors.Wrap(err, "failed to decode hex signature")
	}

	var sig babyjub.SignatureComp
	if len(sigBytes) != len(sig) {
		return ErrInvalidSignatureLength
	}

	copy(sig[:], sigBytes)
	_, err = sig.Decompress()
	if err != nil {
		return errors.Wrap(err, "failed to decompress signature")
	}

	return nil
}

func (p *BJJSignatureProof2021) ProofType() verifiable.ProofType {
	return p.Type
}

func (p *BJJSignatureProof2021) GetCoreClaim() (*core.Claim, error) {
	var coreClaim core.Claim

	if err := coreClaim.FromHex(p.CoreClaim); err != nil {
		return nil, errors.Wrap(err, "failed to get core claim from hex")
	}

	return &coreClaim, nil
}

// Iden3SparseMerkleTreeProof JSON-LD structure
type Iden3SparseMerkleTreeProof struct {
	ID   string               `json:"id"`
	Type verifiable.ProofType `json:"type"`

	IssuerData IssuerData `json:"issuerData"`
	CoreClaim  string     `json:"coreClaim"`

	MTP *mt.Proof `json:"mtp"`
}

func (p *Iden3SparseMerkleTreeProof) UnmarshalJSON(src []byte) error {
	var obj struct {
		ID         string               `json:"id"`
		Type       verifiable.ProofType `json:"type"`
		IssuerData json.RawMessage      `json:"issuerData"`
		CoreClaim  string               `json:"coreClaim"`
		MTP        *mt.Proof            `json:"mtp"`
	}

	if err := json.Unmarshal(src, &obj); err != nil {
		return errors.Wrap(err, "failed to unmarshal proof")
	}

	if obj.Type != verifiable.Iden3SparseMerkleTreeProofType {
		return ErrInvalidProofType
	}

	if err := json.Unmarshal(obj.IssuerData, &p.IssuerData); err != nil {
		return errors.Wrap(err, "failed to unmarshal issuer data")
	}

	if err := validateHexCoreClaim(obj.CoreClaim); err != nil {
		return errors.Wrap(err, "failed to validate core claim")
	}

	p.ID = obj.ID
	p.Type = obj.Type
	p.CoreClaim = obj.CoreClaim
	p.MTP = obj.MTP

	return nil
}

func (p *Iden3SparseMerkleTreeProof) ProofType() verifiable.ProofType {
	return p.Type
}

func (p *Iden3SparseMerkleTreeProof) GetCoreClaim() (*core.Claim, error) {
	var coreClaim core.Claim

	if err := coreClaim.FromHex(p.CoreClaim); err != nil {
		return nil, errors.Wrap(err, "failed to get core claim from hex")
	}

	return &coreClaim, nil
}
