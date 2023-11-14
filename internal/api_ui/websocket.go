package api_ui

import (
	"context"
	"github.com/gorilla/websocket"
	core "github.com/iden3/go-iden3-core"
	"github.com/rarimo/issuer-node/internal/core/domain"
	"github.com/rarimo/issuer-node/internal/core/ports"
	"github.com/rarimo/issuer-node/internal/log"
	"net/http"
	"time"
)

var TickerDuration = 12 * time.Second

type WebsocketResponse struct {
	ctx             context.Context
	request         SubscribeToClaimWebsocketRequestObject
	issuerDID       core.DID
	claimService    ports.ClaimsService
	identityService ports.IdentityService
	hostURL         string
}

func (wr WebsocketResponse) VisitSubscribeToClaimWebsocketResponse(w http.ResponseWriter) error {
	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	value := wr.ctx.Value(ReqReq)
	if value == nil {
		return nil
	}

	request := value.(http.Request)

	c, err := upgrader.Upgrade(w, &request, nil)
	if err != nil {
		log.Error(wr.ctx, "failed to upgrade connection", "err", err)
		return err
	}
	defer c.Close()

	issuerDID, err := core.ParseDID(wr.issuerDID.String())
	if err != nil {
		log.Error(wr.ctx, "failed to parse did", "err", err)
		return err
	}

	ticker := time.NewTicker(TickerDuration)

	go func() {
		for {
			messageType, _, err := c.ReadMessage()
			if err != nil {
				log.Error(wr.ctx, "failed to read message", "err", err)
				return
			}
			if messageType == websocket.CloseMessage {
				return
			}
		}
	}()

	for range ticker.C {
		filter, err := getCredentialsFilter(wr.ctx, &wr.request.UserId, nil, &wr.request.ClaimType, nil)
		if err != nil {
			return err
		}

		claims, err := wr.claimService.GetAll(wr.ctx, *issuerDID, filter)
		if err != nil {
			return err
		}

		if len(claims) == 0 {
			if err := c.WriteMessage(websocket.TextMessage, []byte("processing")); err != nil {
				log.Error(wr.ctx, "failed to write ws message", "err", err)
				break
			}
			continue
		}

		claim := new(domain.Claim)
		for _, claimToProcess := range claims {
			if claimToProcess.IdentityState != nil {
				claim = claimToProcess
			}
		}

		if claim.IdentityState == nil {
			if err := c.WriteMessage(websocket.TextMessage, []byte("processing")); err != nil {
				log.Error(wr.ctx, "failed to write ws message", "err", err)
				break
			}
			continue
		}

		state, err := wr.identityService.GetStateByHash(context.Background(), *claim.IdentityState)
		if err != nil {
			return err
		}

		if state.Status == domain.StatusConfirmed || state.Status == domain.StatusFailed {
			for range ticker.C { // FIXME
				if err = c.WriteJSON(getCredentialQrCodeResponse(claim, wr.hostURL)); err != nil {
					log.Error(wr.ctx, "failed to write ws message", "err", err)
					break
				}
			}
			break
		}
	}
	return nil
}
