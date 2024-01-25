package api

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/rarimo/issuer-node/internal/core/domain"
	"net/http"
	"strings"
)

// CustomQrContentResponse is a wrapper to return any content as an api response.
// Just implement the Visit* method to satisfy the expected interface for that type of response.
type CustomQrContentResponse struct {
	content []byte
}

// NewQrContentResponse returns a new CustomQrContentResponse.
func NewQrContentResponse(response []byte) *CustomQrContentResponse {
	return &CustomQrContentResponse{content: response}
}

// VisitGetQrFromStoreResponse satisfies the AuthQRCodeResponseObject
func (response CustomQrContentResponse) VisitGetQrFromStoreResponse(w http.ResponseWriter) error {
	return response.visit(w)
}

func (response CustomQrContentResponse) visit(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(response.content) // Returning the content without encoding it. It was previously encoded
	return err
}

func getClaimOfferResponse(credential *domain.Claim, hostURL string) ClaimOfferResponse {
	id := uuid.NewString()
	return ClaimOfferResponse{
		Body: struct {
			Credentials []struct {
				Description string `json:"description"`
				Id          string `json:"id"`
			} `json:"Credentials"`
			Url string `json:"url"`
		}{
			Credentials: []struct {
				Description string `json:"description"`
				Id          string `json:"id"`
			}{
				{
					Description: shortType(credential.SchemaType),
					Id:          credential.ID.String(),
				},
			},
			Url: getAgentEndpoint(hostURL),
		},
		From:     credential.Issuer,
		Id:       id,
		ThreadID: id,
		To:       credential.OtherIdentifier,
		Typ:      string(packers.MediaTypePlainMessage),
		Type:     string(protocol.CredentialOfferMessageType),
	}
}

func getAgentEndpoint(hostURL string) string {
	return fmt.Sprintf("%s/v1/agent", strings.TrimSuffix(hostURL, "/"))
}

func shortType(id string) string {
	parts := strings.Split(id, "#")
	l := len(parts)
	if l == 0 {
		return ""
	}
	return parts[l-1]
}
