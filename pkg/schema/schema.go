package schema

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rarimo/issuer-node/internal/log"
	"strings"

	core "github.com/iden3/go-iden3-core"
	jsonSuite "github.com/iden3/go-schema-processor/json"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/jackc/pgtype"

	"github.com/rarimo/issuer-node/internal/common"
	"github.com/rarimo/issuer-node/internal/core/domain"
	"github.com/rarimo/issuer-node/internal/loader"
)

var (
	ErrLoadSchema   = errors.New("cannot load schema")          // ErrLoadSchema Cannot process schema
	ErrValidateData = errors.New("error validating claim data") // ErrValidateData Cannot process schema
	ErrParseClaim   = errors.New("error parsing claim")         // ErrParseClaim Cannot process schema
)

// LoadSchema loads schema from url
func LoadSchema(ctx context.Context, loader loader.Loader) (jsonSuite.Schema, error) {
	var schema jsonSuite.Schema
	schemaBytes, _, err := loader.Load(ctx)
	if err != nil {
		return schema, err
	}
	err = json.Unmarshal(schemaBytes, &schema)

	return schema, err
}

// FromClaimModelToW3CCredential JSON-LD response base on claim
func FromClaimModelToW3CCredential(claim domain.Claim, platformUIHost string) (*verifiable.W3CCredential, error) {
	var cred verifiable.W3CCredential

	err := json.Unmarshal(claim.Data.Bytes, &cred)
	if err != nil {
		return nil, err
	}
	if claim.CredentialStatus.Status == pgtype.Null {
		return nil, fmt.Errorf("credential status is not set")
	}

	proofs := make(verifiable.CredentialProofs, 0)

	var signatureProof *common.BJJSignatureProof2021
	if claim.SignatureProof.Status != pgtype.Null {
		err = claim.SignatureProof.AssignTo(&signatureProof)
		if err != nil {
			return nil, err
		}

		ep := strings.Split(signatureProof.IssuerData.UpdateURL, "/v1/")[1] // FIXME
		signatureProof.IssuerData.UpdateURL = platformUIHost + "/v1/" + ep

		proofs = append(proofs, signatureProof)
	}

	var mtpProof *common.Iden3SparseMerkleTreeProof

	if claim.MTPProof.Status != pgtype.Null {
		err = claim.MTPProof.AssignTo(&mtpProof)
		if err != nil {
			return nil, err
		}

		if mtpProof != nil {
			ep := strings.Split(mtpProof.ID, "/v1/")[1]
			mtpProof.ID = platformUIHost + "/v1/" + ep

			ep = strings.Split(signatureProof.IssuerData.UpdateURL, "/v1/")[1] // FIXME
			mtpProof.IssuerData.UpdateURL = platformUIHost + "/v1/" + ep
		}

		proofs = append(proofs, mtpProof)

	}
	cred.Proof = proofs

	return &cred, nil
}

// FromClaimsModelToW3CCredential JSON-LD response base on claim
func FromClaimsModelToW3CCredential(credentials domain.Credentials, platformUIHost string) ([]*verifiable.W3CCredential, error) {
	w3Credentials := make([]*verifiable.W3CCredential, len(credentials))
	for i := range credentials {
		w3Cred, err := FromClaimModelToW3CCredential(*credentials[i], platformUIHost)
		if err != nil {
			return nil, err
		}

		w3Credentials[i] = w3Cred
	}

	return w3Credentials, nil
}

// Process data and schema and create Index and Value slots
func Process(ctx context.Context, ld loader.Loader, credentialType string, credential verifiable.W3CCredential, options *processor.CoreClaimOptions) (*core.Claim, error) {
	var parser processor.Parser
	var validator processor.Validator
	pr := &processor.Processor{}

	validator = jsonSuite.Validator{}
	parser = jsonSuite.Parser{}

	pr = processor.InitProcessorOptions(pr, processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(ld))

	schema, _, err := pr.Load(ctx)
	if err != nil {
		return nil, ErrLoadSchema
	}

	jsonCredential, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}

	err = pr.ValidateData(jsonCredential, schema)
	if err != nil {
		return nil, ErrValidateData
	}

	claim, err := pr.ParseClaim(ctx, credential, credentialType, schema, options)
	if err != nil {
		log.Error(ctx, "failed to parse claim", "err", err)
		return nil, ErrParseClaim
	}
	return claim, nil
}
