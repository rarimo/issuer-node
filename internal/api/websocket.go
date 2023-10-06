package api

import (
	"context"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	core "github.com/iden3/go-iden3-core"
	"github.com/polygonid/sh-id-platform/internal/core/domain"
	"github.com/polygonid/sh-id-platform/internal/core/ports"
	"github.com/polygonid/sh-id-platform/internal/log"
	"net/http"
	"time"
)

const Ticker = 12

type WebsocketResponse struct {
	ctx             context.Context
	request         SubscribeToClaimWebsocketRequestObject
	claimService    ports.ClaimsService
	identityService ports.IdentityService
}

func (wr WebsocketResponse) VisitSubscribeToClaimWebsocketResponse(w http.ResponseWriter) error {
	var upgrader = websocket.Upgrader{}

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

	issuerDID, err := core.ParseDID(wr.request.Identifier)
	if err != nil {
		log.Error(wr.ctx, "failed to parse did", "err", err)
		return err
	}

	claimUUID, err := uuid.Parse(wr.request.Id)
	if err != nil {
		log.Error(wr.ctx, "failed to parse uuid", "err", err)
		return err
	}

	ticker := time.NewTicker(Ticker * time.Second)

	for range ticker.C {
		claim, err := wr.claimService.GetByID(context.Background(), issuerDID, claimUUID)
		if err != nil {
			log.Error(wr.ctx, "failed to get claim by id", "err", err)
			return err
		}
		if claim == nil || claim.IdentityState == nil {
			log.Error(wr.ctx, "claim not found", claimUUID.String())
			return err
		}

		state, err := wr.identityService.GetStateByHash(context.Background(), *claim.IdentityState)
		if err != nil {
			return err
		}

		if state.Status == domain.StatusConfirmed || state.Status == domain.StatusFailed {
			if err = c.WriteMessage(websocket.TextMessage, []byte(state.Status)); err != nil {
				log.Error(wr.ctx, "failed to write ws message", "err", err)
				break
			}
		}
	}
	return nil
}
