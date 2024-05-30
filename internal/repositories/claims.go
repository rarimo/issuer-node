package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/labstack/gommon/log"
	"github.com/lib/pq"

	"github.com/Masterminds/squirrel"
	"github.com/rarimo/issuer-node/internal/common"
	"github.com/rarimo/issuer-node/internal/core/domain"
	"github.com/rarimo/issuer-node/internal/core/ports"
	"github.com/rarimo/issuer-node/internal/db"
)

const duplicateViolationErrorCode = "23505"

// ErrClaimDuplication claim duplication error
var (
	ErrClaimDuplication = errors.New("claim duplication error")
	// ErrClaimDoesNotExist claim does not exist
	ErrClaimDoesNotExist = errors.New("claim does not exist")
)

type claims struct{}

type dbClaim struct {
	ID               *uuid.UUID
	Identifier       sql.NullString
	Issuer           sql.NullString
	SchemaHash       sql.NullString
	SchemaURL        sql.NullString
	SchemaType       sql.NullString
	OtherIdentifier  sql.NullString
	Expiration       *int64
	Updatable        sql.NullBool
	Version          *int64
	RevNonce         *uint64
	Revoked          sql.NullBool
	Data             *pgtype.JSONB
	CoreClaim        *domain.CoreClaim
	MTPProof         *pgtype.JSONB
	SignatureProof   *pgtype.JSONB
	IdentityState    sql.NullString
	Status           sql.NullString
	CredentialStatus *pgtype.JSONB
	HIndex           sql.NullString
	CreatedAt        *time.Time

	MtProof sql.NullBool
}

// NewClaims returns a new claim repository
func NewClaims() ports.ClaimsRepository {
	return &claims{}
}

func (c *claims) Save(ctx context.Context, conn db.Querier, claim *domain.Claim) (uuid.UUID, error) {
	var err error
	id := claim.ID

	if claim.MTPProof.Status == pgtype.Undefined {
		claim.MTPProof.Status = pgtype.Null
	}
	if claim.Data.Status == pgtype.Undefined {
		claim.Data.Status = pgtype.Null
	}
	if claim.SignatureProof.Status == pgtype.Undefined {
		claim.SignatureProof.Status = pgtype.Null
	}
	if claim.CredentialStatus.Status == pgtype.Undefined {
		claim.CredentialStatus.Status = pgtype.Null
	}

	if id == uuid.Nil {
		s := `INSERT INTO claims (identifier,
                    other_identifier,
                    expiration,
                    updatable,
                    version,
					rev_nonce,
                    signature_proof,
                    issuer,
                    mtp_proof,
                    data,
                    identity_state,
                    schema_hash,
                    schema_url,
                    schema_type,
          			credential_status,
					revoked,
                    core_claim,
                    index_hash,
					mtp, 
					link_id,
                    created_at, 
					schema_type_description)
		VALUES ($1,  $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
		RETURNING id`

		err = conn.QueryRow(ctx, s,
			claim.Identifier,
			claim.OtherIdentifier,
			claim.Expiration,
			claim.Updatable,
			claim.Version,
			claim.RevNonce,
			claim.SignatureProof,
			claim.Issuer,
			claim.MTPProof,
			claim.Data,
			claim.IdentityState,
			claim.SchemaHash,
			claim.SchemaURL,
			claim.SchemaType,
			claim.CredentialStatus,
			claim.Revoked,
			claim.CoreClaim,
			claim.HIndex,
			claim.MtProof,
			claim.LinkID,
			claim.CreatedAt,
			claim.SchemaTypeDescription).Scan(&id)
	} else {
		s := `INSERT INTO claims (
					id,
                    identifier,
                    other_identifier,
                    expiration,
                    updatable,
                    version,
					rev_nonce,
                    signature_proof,
                    issuer,
                    mtp_proof,
                    data,
                    identity_state,
					schema_hash,
                    schema_url,
                    schema_type,
                    credential_status,
                    revoked,
                    core_claim,
                    index_hash,
					mtp,
					link_id,
                    created_at,
					schema_type_description
		)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		)
		ON CONFLICT ON CONSTRAINT claims_pkey 
		DO UPDATE SET 
			( expiration, updatable, version, rev_nonce, signature_proof, mtp_proof, data, identity_state, 
			other_identifier, schema_hash, schema_url, schema_type, issuer, credential_status, revoked, core_claim, mtp, link_id, created_at, schema_type_description)
			= (EXCLUDED.expiration, EXCLUDED.updatable, EXCLUDED.version, EXCLUDED.rev_nonce, EXCLUDED.signature_proof,
		EXCLUDED.mtp_proof, EXCLUDED.data, EXCLUDED.identity_state, EXCLUDED.other_identifier, EXCLUDED.schema_hash, 
		EXCLUDED.schema_url, EXCLUDED.schema_type, EXCLUDED.issuer, EXCLUDED.credential_status, EXCLUDED.revoked, EXCLUDED.core_claim, EXCLUDED.mtp, EXCLUDED.link_id, EXCLUDED.created_at, EXCLUDED.schema_type_description)
			RETURNING id`
		err = conn.QueryRow(ctx, s,
			claim.ID,
			claim.Identifier,
			claim.OtherIdentifier,
			claim.Expiration,
			claim.Updatable,
			claim.Version,
			claim.RevNonce,
			claim.SignatureProof,
			claim.Issuer,
			claim.MTPProof,
			claim.Data,
			claim.IdentityState,
			claim.SchemaHash,
			claim.SchemaURL,
			claim.SchemaType,
			claim.CredentialStatus,
			claim.Revoked,
			claim.CoreClaim,
			claim.HIndex,
			claim.MtProof,
			claim.LinkID,
			claim.CreatedAt,
			claim.SchemaTypeDescription).Scan(&id)
	}

	if err == nil {
		return id, nil
	}

	pqErr, ok := err.(*pq.Error)
	if ok {
		if pqErr.Code == duplicateViolationErrorCode {
			return uuid.Nil, ErrClaimDuplication
		}
	}

	log.Errorf("error saving the claim: %v", "err", err.Error())
	return uuid.Nil, fmt.Errorf("error saving the claim: %w", err)
}

func (c *claims) Revoke(ctx context.Context, conn db.Querier, revocation *domain.Revocation) error {
	_, err := conn.Exec(ctx, `INSERT INTO revocation (identifier, nonce, version, status, description) VALUES($1, $2, $3, $4, $5)`,
		revocation.Identifier,
		revocation.Nonce,
		revocation.Version,
		revocation.Status,
		revocation.Description)
	if err != nil {
		return fmt.Errorf("error revoking the claim: %w", err)
	}

	return nil
}

func (c *claims) Delete(ctx context.Context, conn db.Querier, id uuid.UUID) error {
	sql := `DELETE FROM claims WHERE id = $1`
	cmd, err := conn.Exec(ctx, sql, id.String())
	if err != nil {
		return err
	}

	if cmd.RowsAffected() == 0 {
		return ErrClaimDoesNotExist
	}

	return nil
}

func (c *claims) GetByRevocationNonce(ctx context.Context, conn db.Querier, identifier *w3c.DID, revocationNonce domain.RevNonceUint64) (*domain.Claim, error) {
	claim := domain.Claim{}
	row := conn.QueryRow(
		ctx,
		`SELECT id,
				   issuer,
				   schema_hash,
				   schema_type,
				   schema_url,
				   other_identifier,
				   expiration,
				   updatable,
				   version,
				   rev_nonce,
				   signature_proof,
				   mtp_proof,
				   data,
				   claims.identifier,
				   identity_state,
				   credential_status,
				   core_claim,
				   mtp,
				   schema_type_description
			FROM claims
			LEFT JOIN identity_states ON claims.identity_state = identity_states.state
			WHERE claims.identifier = $1
			  AND claims.rev_nonce = $2`, identifier.String(), revocationNonce)
	err := row.Scan(&claim.ID,
		&claim.Issuer,
		&claim.SchemaHash,
		&claim.SchemaType,
		&claim.SchemaURL,
		&claim.OtherIdentifier,
		&claim.Expiration,
		&claim.Updatable,
		&claim.Version,
		&claim.RevNonce,
		&claim.SignatureProof,
		&claim.MTPProof,
		&claim.Data,
		&claim.Identifier,
		&claim.IdentityState,
		&claim.CredentialStatus,
		&claim.CoreClaim,
		&claim.MtProof,
		&claim.SchemaTypeDescription)

	if err != nil && err == pgx.ErrNoRows {
		return nil, ErrClaimDoesNotExist
	}

	if err != nil {
		return nil, fmt.Errorf("error getting the claim by nonce: %w", err)
	}

	return &claim, nil
}

func (c *claims) FindOneClaimBySchemaHash(ctx context.Context, conn db.Querier, subject *w3c.DID, schemaHash string) (*domain.Claim, error) {
	var claim domain.Claim

	row := conn.QueryRow(ctx,
		`SELECT claims.id,
		   issuer,
		   schema_hash,
		   schema_type,
		   schema_url,
		   other_identifier,
		   expiration,
		   updatable,
		   claims.version,
		   rev_nonce,
		   mtp_proof,
		   signature_proof,
		   data,
		   claims.identifier,
		   identity_state,
		   credential_status,
		   revoked,
		   core_claim,
           schema_type_description
		FROM claims
		WHERE claims.identifier=$1  
				AND ( claims.other_identifier = $1 or claims.other_identifier = '') 
				AND claims.schema_hash = $2 
				AND claims.revoked = false`, subject.String(), schemaHash)

	err := row.Scan(&claim.ID,
		&claim.Issuer,
		&claim.SchemaHash,
		&claim.SchemaType,
		&claim.SchemaHash,
		&claim.OtherIdentifier,
		&claim.Expiration,
		&claim.Updatable,
		&claim.Version,
		&claim.RevNonce,
		&claim.MTPProof,
		&claim.SignatureProof,
		&claim.Data,
		&claim.Identifier,
		&claim.IdentityState,
		&claim.CredentialStatus,
		&claim.Revoked,
		&claim.CoreClaim,
		&claim.SchemaTypeDescription)

	if err == pgx.ErrNoRows {
		return nil, ErrClaimDoesNotExist
	}

	return &claim, err
}

func (c *claims) RevokeNonce(ctx context.Context, conn db.Querier, revocation *domain.Revocation) error {
	_, err := conn.Exec(ctx,
		`	INSERT INTO revocation (identifier, nonce, version, status, description) 
				VALUES($1, $2, $3, $4, $5)`,
		revocation.Identifier,
		revocation.Nonce,
		revocation.Version,
		revocation.Status,
		revocation.Description)
	return err
}

// GetByIdAndIssuer get claim by id
func (c *claims) GetByIdAndIssuer(ctx context.Context, conn db.Querier, identifier *w3c.DID, claimID uuid.UUID) (*domain.Claim, error) {
	claim := domain.Claim{}
	err := conn.QueryRow(ctx,
		`SELECT id,
       				issuer,
       				schema_hash,
       				schema_type,
       				schema_url,
       				other_identifier,
       				expiration,
       				updatable,
       				version,
        			rev_nonce,
       				signature_proof,
       				mtp_proof,
       				data,
       				claims.identifier,
        			identity_state,
       				credential_status,
       				core_claim,
					mtp,
					revoked,
					link_id,
					schema_type_description
        FROM claims
        WHERE claims.identifier = $1 AND claims.id = $2`, identifier.String(), claimID).Scan(
		&claim.ID,
		&claim.Issuer,
		&claim.SchemaHash,
		&claim.SchemaType,
		&claim.SchemaURL,
		&claim.OtherIdentifier,
		&claim.Expiration,
		&claim.Updatable,
		&claim.Version,
		&claim.RevNonce,
		&claim.SignatureProof,
		&claim.MTPProof,
		&claim.Data,
		&claim.Identifier,
		&claim.IdentityState,
		&claim.CredentialStatus,
		&claim.CoreClaim,
		&claim.MtProof,
		&claim.Revoked,
		&claim.LinkID,
		&claim.SchemaTypeDescription)

	if err != nil && err == pgx.ErrNoRows {
		return nil, ErrClaimDoesNotExist
	}

	return &claim, err
}

// GetById get claim by id
func (c *claims) GetById(ctx context.Context, conn db.Querier, claimID uuid.UUID) (*domain.Claim, error) {
	claim := domain.Claim{}
	err := conn.QueryRow(ctx,
		`SELECT id,
       				issuer,
       				schema_hash,
       				schema_type,
       				schema_url,
       				other_identifier,
       				expiration,
       				updatable,
       				version,
        			rev_nonce,
       				signature_proof,
       				mtp_proof,
       				data,
       				claims.identifier,
        			identity_state,
       				credential_status,
       				core_claim,
					mtp,
					revoked,
					link_id
        FROM claims
        WHERE claims.id = $1`, claimID).Scan(
		&claim.ID,
		&claim.Issuer,
		&claim.SchemaHash,
		&claim.SchemaType,
		&claim.SchemaURL,
		&claim.OtherIdentifier,
		&claim.Expiration,
		&claim.Updatable,
		&claim.Version,
		&claim.RevNonce,
		&claim.SignatureProof,
		&claim.MTPProof,
		&claim.Data,
		&claim.Identifier,
		&claim.IdentityState,
		&claim.CredentialStatus,
		&claim.CoreClaim,
		&claim.MtProof,
		&claim.Revoked,
		&claim.LinkID)

	if err != nil && err == pgx.ErrNoRows {
		return nil, ErrClaimDoesNotExist
	}

	return &claim, err
}

// GetAllByIssuerID returns all the claims of the given issuer
func (c *claims) GetAllByIssuerID(ctx context.Context, conn db.Querier, issuerID w3c.DID, filter *ports.ClaimsFilter) ([]*domain.Claim, error) {
	query, args := buildGetAllQueryAndFilters(issuerID, filter)

	rows, err := conn.Query(ctx, query, args...)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrClaimDoesNotExist
		}

		return nil, err
	}
	defer rows.Close()

	return processClaims(rows)
}

func (c *claims) GetNonRevokedByConnectionAndIssuerID(ctx context.Context, conn db.Querier, connID uuid.UUID, issuerID w3c.DID) ([]*domain.Claim, error) {
	query := `SELECT claims.id,
				   issuer,
				   schema_hash,
				   schema_url,
				   schema_type,
				   other_identifier,
				   expiration,
				   updatable,
				   claims.version,
				   rev_nonce,
				   signature_proof,
				   mtp_proof,
				   data,
				   claims.identifier,
				   identity_state,
				   identity_states.status,
				   credential_status,
				   core_claim,
				   revoked,
				   mtp
			FROM claims
			JOIN connections ON connections.issuer_id = claims.issuer AND connections.user_id = claims.other_identifier
			LEFT JOIN identity_states  ON claims.identity_state = identity_states.state
			WHERE connections.id = $1 AND claims.issuer = $2 AND  claims.revoked = false
			`

	rows, err := conn.Query(ctx, query, connID.String(), issuerID.String())

	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}

	defer rows.Close()

	return processClaims(rows)
}

func (c *claims) GetAllByState(ctx context.Context, conn db.Querier, did *w3c.DID, state *merkletree.Hash) (claims []domain.Claim, err error) {
	claims = make([]domain.Claim, 0)
	var rows pgx.Rows
	if state == nil {
		rows, err = conn.Query(ctx,
			`
		SELECT id,
			issuer,
			schema_hash,
			schema_url,
			schema_type,
			other_identifier,
			expiration,
			updatable,
			version,
			rev_nonce,
			signature_proof,
			mtp_proof,
			data,
			identifier,
			identity_state,
			NULL AS status,
			credential_status,
			core_claim 
		FROM claims
		WHERE issuer = $1 AND identity_state IS NULL AND identifier = issuer
		`, did.String())
	} else {
		rows, err = conn.Query(ctx, `
		SELECT
			id,
			issuer,
			schema_hash,
			schema_url,
			schema_type,
			other_identifier,
			expiration,
			updatable,
			version,
			rev_nonce,
			signature_proof,
			mtp_proof,
			data,
			claims.identifier,
			identity_state,
			status,
			credential_status,
			core_claim 
		FROM claims
		  LEFT OUTER JOIN identity_states ON claims.identity_state = identity_states.state
		WHERE issuer = $1 AND identity_state = $2 AND claims.identifier = issuer
		`, did.String(), state.Hex())
	}

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var claim domain.Claim
		err := rows.Scan(&claim.ID,
			&claim.Issuer,
			&claim.SchemaHash,
			&claim.SchemaURL,
			&claim.SchemaType,
			&claim.OtherIdentifier,
			&claim.Expiration,
			&claim.Updatable,
			&claim.Version,
			&claim.RevNonce,
			&claim.SignatureProof,
			&claim.MTPProof,
			&claim.Data,
			&claim.Identifier,
			&claim.IdentityState,
			&claim.Status,
			&claim.CredentialStatus,
			&claim.CoreClaim)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	}

	return claims, err
}

func (c *claims) GetAllByStateWithMTProof(ctx context.Context, conn db.Querier, did *w3c.DID, state *merkletree.Hash) (claims []domain.Claim, err error) {
	claims = make([]domain.Claim, 0)
	var rows pgx.Rows
	if state == nil {
		rows, err = conn.Query(ctx,
			`
		SELECT id,
			issuer,
			schema_hash,
			schema_url,
			schema_type,
			other_identifier,
			expiration,
			updatable,
			version,
			rev_nonce,
			signature_proof,
			mtp_proof,
			data,
			identifier,
			identity_state,
			NULL AS status,
			credential_status,
			core_claim 
		FROM claims
		WHERE issuer = $1 AND identity_state IS NULL AND identifier = issuer AND mtp = true
		`, did.String())
	} else {
		rows, err = conn.Query(ctx, `
		SELECT
			id,
			issuer,
			schema_hash,
			schema_url,
			schema_type,
			other_identifier,
			expiration,
			updatable,
			version,
			rev_nonce,
			signature_proof,
			mtp_proof,
			data,
			claims.identifier,
			identity_state,
			status,
			credential_status,
			core_claim 
		FROM claims
		  LEFT OUTER JOIN identity_states ON claims.identity_state = identity_states.state
		WHERE issuer = $1 AND identity_state = $2 AND claims.identifier = issuer AND mtp = true
		`, did.String(), state.Hex())
	}

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var claim domain.Claim
		err := rows.Scan(&claim.ID,
			&claim.Issuer,
			&claim.SchemaHash,
			&claim.SchemaURL,
			&claim.SchemaType,
			&claim.OtherIdentifier,
			&claim.Expiration,
			&claim.Updatable,
			&claim.Version,
			&claim.RevNonce,
			&claim.SignatureProof,
			&claim.MTPProof,
			&claim.Data,
			&claim.Identifier,
			&claim.IdentityState,
			&claim.Status,
			&claim.CredentialStatus,
			&claim.CoreClaim)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	}

	return claims, err
}

func (c *claims) UpdateState(ctx context.Context, conn db.Querier, claim *domain.Claim) (int64, error) {
	query := "UPDATE claims SET identity_state = $1 WHERE id = $2 AND identifier = $3"
	res, err := conn.Exec(ctx, query, *claim.IdentityState, claim.ID, claim.Identifier)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

func processClaims(rows pgx.Rows) ([]*domain.Claim, error) {
	claims := make([]*domain.Claim, 0)

	for rows.Next() {
		var claim domain.Claim
		err := rows.Scan(&claim.ID,
			&claim.Issuer,
			&claim.SchemaHash,
			&claim.SchemaURL,
			&claim.SchemaType,
			&claim.OtherIdentifier,
			&claim.Expiration,
			&claim.Updatable,
			&claim.Version,
			&claim.RevNonce,
			&claim.SignatureProof,
			&claim.MTPProof,
			&claim.Data,
			&claim.Identifier,
			&claim.IdentityState,
			&claim.Status,
			&claim.CredentialStatus,
			&claim.CoreClaim,
			&claim.Revoked,
			&claim.MtProof)
		if err != nil {
			return nil, err
		}
		claims = append(claims, &claim)
	}

	return claims, rows.Err()
}

func buildGetAllQueryAndFilters(issuerID w3c.DID, filter *ports.ClaimsFilter) (string, []interface{}) {
	query := `SELECT claims.id,
				   issuer,
				   schema_hash,
				   schema_url,
				   schema_type,
				   other_identifier,
				   expiration,
				   updatable,
				   claims.version,
				   rev_nonce,
				   signature_proof,
				   mtp_proof,
				   data,
				   claims.identifier,
				   identity_state,
				   identity_states.status,
				   credential_status,
				   core_claim,
				   revoked,
				   mtp
			FROM claims
			LEFT JOIN identity_states  ON claims.identity_state = identity_states.state
			`
	if filter.FTSQuery != "" {
		query = fmt.Sprintf("%s LEFT JOIN schemas ON claims.schema_hash=schemas.hash AND claims.issuer=schemas.issuer_id ", query)
	}

	filters := []interface{}{issuerID.String()}
	query = fmt.Sprintf("%s WHERE claims.identifier = $%d ", query, len(filters))

	query = fmt.Sprintf("%s AND claims.schema_type <> '%s' ", query, domain.AuthBJJCredentialSchemaType)

	if filter.Self != nil && *filter.Self {
		query = fmt.Sprintf("%s and other_identifier = '' ", query)
	}
	if filter.Subject != "" {
		filters = append(filters, filter.Subject)
		query = fmt.Sprintf("%s and other_identifier = $%d ", query, len(filters))
	}
	if filter.SchemaHash != "" {
		filters = append(filters, fmt.Sprintf("%s%%", filter.SchemaHash))
		query = fmt.Sprintf("%s and schema_hash like $%d", query, len(filters))
	}
	if filter.SchemaType != "" {
		filters = append(filters, fmt.Sprintf("%%%s%%", filter.SchemaType))
		query = fmt.Sprintf("%s and schema_type like $%d", query, len(filters))
	}
	if filter.Revoked != nil {
		filters = append(filters, *filter.Revoked)
		query = fmt.Sprintf("%s and claims.revoked = $%d", query, len(filters))
	}
	if filter.QueryField != "" {
		filters = append(filters, filter.QueryField, filter.QueryFieldValue)
		query = fmt.Sprintf("%s and data -> 'credentialSubject'  ->>$%d = $%d ", query, len(filters)-1, len(filters))
	}
	if filter.ExpiredOn != nil {
		t := *filter.ExpiredOn
		filters = append(filters, t.Unix())
		query = fmt.Sprintf("%s AND claims.expiration>0 AND claims.expiration<$%d", query, len(filters))
	}
	if len(filter.Proofs) > 0 {
		for _, proof := range filter.Proofs {
			switch proof {
			case verifiable.BJJSignatureProofType:
				query = fmt.Sprintf("%s AND claims.signature_proof IS NOT NULL", query)
			case verifiable.Iden3SparseMerkleTreeProofType:
				query = fmt.Sprintf("%s AND claims.mtp_proof IS NOT NULL", query)
			case domain.AnyProofType:
				query = fmt.Sprintf("%s AND ((claims.mtp = true AND claims.mtp_proof IS NOT NULL) OR claims.signature_proof IS NOT NULL)", query)
			}
		}
	}
	if filter.FTSQuery != "" {
		cond := "OR"
		if filter.FTSAndCond {
			cond = "AND"
		}
		terms := tokenizeQuery(filter.FTSQuery)
		ftsConds := buildPartialQueryLikes("schemas.words", cond, 1+len(filters), len(terms))
		for _, term := range terms {
			filters = append(filters, term)
		}
		if filter.Subject == "" {
			ftsConds += fmt.Sprintf(" %s %s", cond, buildPartialQueryDidLikes("claims.other_identifier", tokenizeQuery(filter.FTSQuery), cond))
		}
		query = fmt.Sprintf("%s AND (%s) ", query, ftsConds)
	}

	query += " ORDER BY claims.created_at DESC"

	return query, filters
}

func (c *claims) UpdateClaimMTP(ctx context.Context, conn db.Querier, claim *domain.Claim) (int64, error) {
	query := "UPDATE claims SET mtp_proof = $1 WHERE id = $2 AND identifier = $3"
	res, err := conn.Exec(ctx, query, claim.MTPProof, claim.ID, claim.Identifier)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

// GetAuthClaimsForPublishing of all claims for identity
func (c *claims) GetAuthClaimsForPublishing(ctx context.Context, conn db.Querier, identifier *w3c.DID, publishingState string, schemaHash string) ([]*domain.Claim, error) {
	var err error
	query := `SELECT claims.id,
		issuer,
       	schema_hash,
       	schema_type,
       	schema_url,
       	other_identifier,
       	expiration,
       	updatable,
       	claims.version,     
		rev_nonce,
       	signature_proof,
       	mtp_proof,
       	data,
       	claims.identifier,    
		identity_state,     
		identity_states.status,
       	credential_status,
       	core_claim,
       	revoked,
		mtp
	FROM claims
	LEFT JOIN identity_states  ON claims.identity_state = identity_states.state
	LEFT JOIN revocation  ON claims.rev_nonce = revocation.nonce AND claims.issuer = revocation.identifier
	WHERE claims.identifier = $1 
			AND state != $2
			AND claims.schema_hash = $3
			AND revocation.nonce IS NULL `

	rows, err := conn.Query(ctx, query, identifier.String(), publishingState, schemaHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	claims, err := processClaims(rows)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (c *claims) GetClaimsIssuedForUser(ctx context.Context, conn db.Querier, identifier w3c.DID, userDID w3c.DID, linkID uuid.UUID) ([]*domain.Claim, error) {
	query := `SELECT claims.id,
		   issuer,
		   schema_hash,
		   schema_type,
		   schema_url,
		   other_identifier,
		   expiration,
		   updatable,
		   claims.version,
		   rev_nonce,
		   mtp_proof,
		   signature_proof,
		   data,
		   claims.identifier,
		   identity_state,
		   credential_status,
		   revoked,
		   core_claim
		FROM claims
		WHERE claims.identifier = $1 
		AND claims.other_identifier = $2
		AND claims.link_id = $3
	`
	rows, err := conn.Query(ctx, query, identifier.String(), userDID.String(), linkID)
	if err != nil {
		return nil, err
	}

	claims := make([]*domain.Claim, 0)

	for rows.Next() {
		var claim domain.Claim
		err := rows.Scan(&claim.ID,
			&claim.Issuer,
			&claim.SchemaHash,
			&claim.SchemaType,
			&claim.SchemaHash,
			&claim.OtherIdentifier,
			&claim.Expiration,
			&claim.Updatable,
			&claim.Version,
			&claim.RevNonce,
			&claim.MTPProof,
			&claim.SignatureProof,
			&claim.Data,
			&claim.Identifier,
			&claim.IdentityState,
			&claim.CredentialStatus,
			&claim.Revoked,
			&claim.CoreClaim)
		if err != nil {
			return nil, err
		}
		claims = append(claims, &claim)
	}

	defer rows.Close()
	return claims, nil
}

func (c *claims) GetByStateIDWithMTPProof(ctx context.Context, conn db.Querier, did *w3c.DID, state string) ([]*domain.Claim, error) {
	query := `SELECT claims.id,
		   issuer,
		   schema_hash,
		   schema_type,
		   schema_url,
		   other_identifier,
		   expiration,
		   updatable,
		   claims.version,
		   rev_nonce,
		   mtp_proof,
		   signature_proof,
		   data,
		   claims.identifier,
		   identity_state,
		   credential_status,
		   revoked,
		   core_claim
		FROM claims
		WHERE claims.identifier = $1
		AND identity_state = $2
		AND mtp_proof IS NOT NULL
	`
	rows, err := conn.Query(ctx, query, did.String(), state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	claims := make([]*domain.Claim, 0)

	for rows.Next() {
		var claim domain.Claim
		err := rows.Scan(&claim.ID,
			&claim.Issuer,
			&claim.SchemaHash,
			&claim.SchemaType,
			&claim.SchemaHash,
			&claim.OtherIdentifier,
			&claim.Expiration,
			&claim.Updatable,
			&claim.Version,
			&claim.RevNonce,
			&claim.MTPProof,
			&claim.SignatureProof,
			&claim.Data,
			&claim.Identifier,
			&claim.IdentityState,
			&claim.CredentialStatus,
			&claim.Revoked,
			&claim.CoreClaim)
		if err != nil {
			return nil, err
		}
		claims = append(claims, &claim)
	}

	return claims, nil
}

func (c *claims) CountTotal(ctx context.Context, conn db.Querier, params ports.ClaimsCountParams, vcType *string) (int64, error) {
	var res int64
	err := conn.QueryRow(ctx, `SELECT COUNT(id) FROM claims`).Scan(&res)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return res, err
}

func (c *claims) CountGrouped(ctx context.Context, conn db.Querier, params ports.ClaimsCountParams) (dates []string, counts []int64, err error) {
	head := `SELECT
		to_char(date_trunc($1, created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD HH24:MI:SS') AS date,
		COUNT(id) AS count
		FROM claims`
	tail := `GROUP BY date ORDER BY date DESC LIMIT $2`

	where := make([]string, 0, 2)
	if params.Since != nil {
		where = append(where, fmt.Sprintf("created_at >= '%s'", params.Since.Format(time.RFC3339)))
	}
	if params.Until != nil {
		where = append(where, fmt.Sprintf("created_at <= '%s'", params.Until.Format(time.RFC3339)))
	}
	if len(where) > 0 {
		head = fmt.Sprintf("%s WHERE %s", head, strings.Join(where, " AND "))
	}

	query := fmt.Sprintf("%s %s", head, tail)
	rows, err := conn.Query(ctx, query, params.GroupByDate, params.Limit)
	if err != nil {
		return
	}
	defer rows.Close()

	const optCap = 128 // how much memory to sacrifice for quick slice appending
	dates = make([]string, 0, optCap)
	counts = make([]int64, 0, optCap)

	for rows.Next() {
		var date string
		var count int64
		if err = rows.Scan(&date, &count); err != nil {
			return
		}
		dates = append(dates, date)
		counts = append(counts, count)
	}

	err = rows.Err()
	return
}

func (c *claims) Count(ctx context.Context, conn db.Querier, params ports.ClaimsCountParams) (ports.ClaimsCountResult, error) {
	q := buildClaimsGroupedCountQuery(params)
	str, args, err := q.ToSql()
	if err != nil {
		panic(err) // engineer's error in buildClaimsGroupedCountQuery
	}

	rows, err := conn.Query(ctx, str, args...)
	if err != nil {
		return ports.ClaimsCountResult{}, err
	}
	defer rows.Close()

	return scanClaimsGroupedCountResult(params, rows)
}

func buildClaimsGroupedCountQuery(params ports.ClaimsCountParams) squirrel.SelectBuilder {
	const (
		typeColumn      = "schema_type_description"
		createdAtColumn = "created_at"
	)
	q := squirrel.Select("COUNT(id) AS count").From("claims")

	if len(params.FilterByType) > 0 {
		q = q.Where(squirrel.Eq{typeColumn: params.FilterByType})
	}
	if params.Since != nil {
		q = q.Where(squirrel.GtOrEq{createdAtColumn: *params.Since})
	}
	if params.Until != nil {
		q = q.Where(squirrel.LtOrEq{createdAtColumn: *params.Until})
	}

	if params.GroupByDate != "" {
		q = q.Column("to_char(date_trunc($1, created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD HH24:MI:SS') AS date",
			params.GroupByDate).
			GroupBy("date").
			OrderBy("date DESC").
			Limit(params.Limit)
	}

	if params.GroupByType {
		q = q.Column(typeColumn).GroupBy(typeColumn).OrderBy(typeColumn).Limit(params.Limit)
	}

	return q
}

func scanClaimsGroupedCountResult(params ports.ClaimsCountParams, rows pgx.Rows) (res ports.ClaimsCountResult, err error) {
	var (
		byType        = params.GroupByType && params.GroupByDate == ""
		byDate        = params.GroupByDate != "" && !params.GroupByType
		byTypeAndDate = params.GroupByDate != "" && params.GroupByType
	)

	if !byType && !byDate {
		res.Total = new(int64)
		rows.Next()
		err = rows.Scan(res.Total)
		return
	}

	const optCap = 128 // how much memory to sacrifice for quick slice appending
	var (
		dates  = make([]string, 0, optCap)
		counts = make([]int64, 0, optCap)
		types  = make([]string, 0, optCap)
		date   string
		count  int64
		typ    string
	)

	// based on SelectBuilder calls, the order is count, type, date
	for rows.Next() {
		switch {
		case byDate:
			err = rows.Scan(&count, &date)
			dates = append(dates, date)
		case byType:
			err = rows.Scan(&count, &typ)
			types = append(types, typ)
		case byTypeAndDate:
			err = rows.Scan(&count, &typ, &date)
			types = append(types, typ)
			dates = append(dates, date)
		}
		counts = append(counts, count)
		if err != nil {
			return
		}
	}
	if err = rows.Err(); err != nil {
		return
	}
	// TODO. what if len(dates) != len(counts) or len(types) != len(counts) or len(dates) != len(types)?

	switch {
	case byDate:
		res.ByDate.Dates = dates
		res.ByDate.Counts = counts
	case byType:
		res.ByType = make(map[string]int64, len(types))
		for i, t := range types {
			res.ByType[t] = counts[i]
		}
	case byTypeAndDate:
		res.ByTypeAndDate = make(map[string]ports.ClaimsCountByDatesResult, len(types))
		for i, t := range types {
			// FIXME. this is inefficient, probably
			res.ByTypeAndDate[t] = ports.ClaimsCountByDatesResult{
				Dates:  append(res.ByTypeAndDate[t].Dates, dates[i]),
				Counts: append(res.ByTypeAndDate[t].Counts, counts[i]),
			}
		}
	}
	return
}

func toCredentialDomain(c *dbClaim) *domain.Claim {
	if c.ID == nil {
		return nil
	}

	credential := &domain.Claim{
		ID: *c.ID,
	}

	if c.CoreClaim != nil {
		credential.CoreClaim = *c.CoreClaim
	}
	if c.Data != nil {
		credential.Data = *c.Data
	}
	if c.SignatureProof != nil {
		credential.SignatureProof = *c.SignatureProof
	}
	if c.CredentialStatus != nil {
		credential.CredentialStatus = *c.CredentialStatus
	}
	if c.Identifier.Valid {
		credential.Identifier = common.ToPointer(c.Identifier.String)
	}
	if c.Issuer.Valid {
		credential.Issuer = c.Issuer.String
	}
	if c.SchemaHash.Valid {
		credential.SchemaHash = c.SchemaHash.String
	}
	if c.SchemaURL.Valid {
		credential.SchemaURL = c.SchemaURL.String
	}
	if c.SchemaType.Valid {
		credential.SchemaType = c.SchemaType.String
	}
	if c.OtherIdentifier.Valid {
		credential.OtherIdentifier = c.OtherIdentifier.String
	}
	if c.Expiration != nil {
		credential.Expiration = *c.Expiration
	}
	if c.Updatable.Valid {
		credential.Updatable = c.Updatable.Bool
	}
	if c.RevNonce != nil {
		credential.RevNonce = domain.RevNonceUint64(*c.RevNonce)
	}
	if c.Revoked.Valid {
		credential.Revoked = c.Revoked.Bool
	}
	if c.IdentityState.Valid {
		credential.IdentityState = common.ToPointer(c.IdentityState.String)
	}
	if c.Status.Valid {
		credential.Status = common.ToPointer(domain.IdentityStatus(c.Status.String))
	}
	if c.HIndex.Valid {
		credential.HIndex = c.HIndex.String
	}
	if c.MtProof.Valid {
		credential.MtProof = c.MtProof.Bool
	}

	return credential
}
