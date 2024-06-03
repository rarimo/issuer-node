package ports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	comm "github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/protocol"

	"github.com/rarimo/issuer-node/internal/common"
	"github.com/rarimo/issuer-node/internal/core/domain"
)

// CreateClaimRequest struct
type CreateClaimRequest struct {
	DID                   *w3c.DID
	Schema                string
	CredentialSubject     map[string]any
	Expiration            *time.Time
	Type                  string
	Version               uint32
	SubjectPos            string
	MerklizedRootPosition string
	SignatureProof        bool
	MTProof               bool
	LinkID                *uuid.UUID
	SingleIssuer          bool
	CredentialStatusType  verifiable.CredentialStatusType
	SchemaTypeDescription string
}

// AgentRequest struct
type AgentRequest struct {
	Body      json.RawMessage
	ThreadID  string
	IssuerDID *w3c.DID
	UserDID   *w3c.DID
	ClaimID   uuid.UUID
	Typ       comm.MediaType
	Type      comm.ProtocolMessage
}

// ClaimsFilter struct
type ClaimsFilter struct {
	Self            *bool
	Revoked         *bool
	ExpiredOn       *time.Time
	SchemaHash      string
	SchemaType      string
	Subject         string
	QueryField      string
	QueryFieldValue string
	FTSQuery        string
	FTSAndCond      bool
	Proofs          []verifiable.ProofType
}

type ClaimsCountParams struct {
	GroupByDate  string
	GroupByType  bool
	FilterByType []string
	Limit        uint64
	Since        *time.Time
	Until        *time.Time
}

type ClaimsCountResult struct {
	Total  *int64
	Counts []int64
	Dates  []string
	Types  []string
	// map(date -> map(type -> count))
	DatesTypes map[string]map[string]int64
}

// NewClaimsFilter returns a valid claims filter
func NewClaimsFilter(schemaHash, schemaType, subject, queryField, queryValue *string, self, revoked *bool) (*ClaimsFilter, error) {
	var filter ClaimsFilter

	if self != nil && *self {
		if subject != nil && *subject != "" {
			return nil, fmt.Errorf("self and subject filter cannot be used together")
		}
		filter.Self = self
	}
	if schemaHash != nil {
		filter.SchemaHash = *schemaHash
	}
	if schemaType != nil {
		filter.SchemaType = *schemaType
	}
	if revoked != nil {
		filter.Revoked = revoked
	}
	if subject != nil {
		filter.Subject = *subject
	}
	if queryField != nil {
		filter.QueryField = *queryField
	}
	if queryValue != nil {
		filter.QueryFieldValue = *queryValue
	}

	return &filter, nil
}

// NewCreateClaimRequest returns a new claim object with the given parameters
func NewCreateClaimRequest(did *w3c.DID, credentialSchema string, credentialSubject map[string]any, expiration *time.Time, typ string, cVersion *uint32, subjectPos *string, merklizedRootPosition *string, sigProof *bool, mtProof *bool, linkID *uuid.UUID, singleIssuer bool, credentialStatusType verifiable.CredentialStatusType) *CreateClaimRequest {
	if sigProof == nil {
		sigProof = common.ToPointer(false)
	}

	if mtProof == nil {
		mtProof = common.ToPointer(false)
	}

	req := &CreateClaimRequest{
		DID:               did,
		Schema:            credentialSchema,
		CredentialSubject: credentialSubject,
		Type:              typ,
		SignatureProof:    *sigProof,
		MTProof:           *mtProof,
	}
	if expiration != nil {
		req.Expiration = expiration
	}
	if cVersion != nil {
		req.Version = *cVersion
	}
	if subjectPos != nil {
		req.SubjectPos = *subjectPos
	}
	if merklizedRootPosition != nil {
		req.MerklizedRootPosition = *merklizedRootPosition
	}

	req.LinkID = linkID
	req.SingleIssuer = singleIssuer
	req.CredentialStatusType = credentialStatusType
	return req
}

// NewAgentRequest validates the inputs and returns a new AgentRequest
func NewAgentRequest(basicMessage *comm.BasicMessage) (*AgentRequest, error) {
	if basicMessage.To == "" {
		return nil, fmt.Errorf("'to' field cannot be empty")
	}

	toDID, err := w3c.ParseDID(basicMessage.To)
	if err != nil {
		return nil, err
	}

	if basicMessage.From == "" {
		return nil, fmt.Errorf("'from' field cannot be empty")
	}

	fromDID, err := w3c.ParseDID(basicMessage.From)
	if err != nil {
		return nil, err
	}

	if basicMessage.ID == "" {
		return nil, fmt.Errorf("'id' field cannot be empty")
	}

	claimID, err := uuid.Parse(basicMessage.ID)
	if err != nil {
		return nil, err
	}

	if basicMessage.Type != protocol.CredentialFetchRequestMessageType && basicMessage.Type != protocol.RevocationStatusRequestMessageType {
		return nil, fmt.Errorf("invalid type")
	}

	if basicMessage.ID == "" {
		return nil, fmt.Errorf("'id' field cannot be empty")
	}

	return &AgentRequest{
		Body:      basicMessage.Body,
		UserDID:   fromDID,
		IssuerDID: toDID,
		ThreadID:  basicMessage.ThreadID,
		ClaimID:   claimID,
		Typ:       basicMessage.Typ,
		Type:      basicMessage.Type,
	}, nil
}

func NewClaimsCountParams(
	byDate string,
	byType *bool,
	filter *[]string,
	limit *uint64,
	since, until *string,
	lastDays *int,
) (params ClaimsCountParams, err error) {

	const timeFormat = "2006-01-02 15:04:05"
	const maxLastDays = 365000

	params.GroupByDate = byDate
	if byType != nil {
		params.GroupByType = *byType
	}
	if filter != nil {
		params.FilterByType = *filter
	}

	params.Limit = 100
	if limit != nil && *limit > 0 {
		params.Limit = *limit
	}

	if since != nil {
		params.Since = new(time.Time)
		*params.Since, err = time.Parse(timeFormat, *since)
		if err != nil {
			err = fmt.Errorf("invalid since field: %w", err)
			return
		}
	}

	if until != nil {
		params.Until = new(time.Time)
		*params.Until, err = time.Parse(timeFormat, *until)
		if err != nil {
			err = fmt.Errorf("invalid until field: %w", err)
			return
		}
	}

	if lastDays != nil {
		if *lastDays > maxLastDays {
			err = errors.New("lastDays field out of range")
			return
		}

		params.Since = new(time.Time)
		*params.Since = time.Now().UTC().AddDate(0, 0, -*lastDays)
	}

	return
}

// ClaimsService is the interface implemented by the claim service
type ClaimsService interface {
	Save(ctx context.Context, claimReq *CreateClaimRequest) (*domain.Claim, error)
	CreateCredential(ctx context.Context, req *CreateClaimRequest) (*domain.Claim, error)
	Revoke(ctx context.Context, id w3c.DID, nonce uint64, description string) error
	GetAll(ctx context.Context, did w3c.DID, filter *ClaimsFilter) ([]*domain.Claim, error)
	RevokeAllFromConnection(ctx context.Context, connID uuid.UUID, issuerID w3c.DID) error
	GetRevocationStatus(ctx context.Context, issuerDID w3c.DID, nonce uint64, stateHash string) (*verifiable.RevocationStatus, error)
	GetByID(ctx context.Context, issID *w3c.DID, id uuid.UUID) (*domain.Claim, error)
	GetBySingleID(ctx context.Context, id uuid.UUID) (*domain.Claim, error)
	GetCredentialQrCode(ctx context.Context, issID *w3c.DID, id uuid.UUID, hostURL string) (string, string, error)
	Agent(ctx context.Context, req *AgentRequest) (*domain.Agent, error)
	GetAuthClaim(ctx context.Context, did *w3c.DID) (*domain.Claim, error)
	GetAuthClaimForPublishing(ctx context.Context, did *w3c.DID, state string) (*domain.Claim, error)
	UpdateClaimsMTPAndState(ctx context.Context, currentState *domain.IdentityState) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetByStateIDWithMTPProof(ctx context.Context, did *w3c.DID, state string) ([]*domain.Claim, error)
	GetMTProof(ctx context.Context, leafKey *big.Int, root *merkletree.Hash, merkleTreeID int64) (*merkletree.Proof, error)
	GetMTIDByKey(ctx context.Context, key string) (int64, error)
	Count(ctx context.Context, params ClaimsCountParams) (ClaimsCountResult, error)
}
