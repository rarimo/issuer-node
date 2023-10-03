package api

import (
	"context"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	core "github.com/iden3/go-iden3-core"
	"github.com/polygonid/sh-id-platform/internal/core/domain"
	"github.com/polygonid/sh-id-platform/internal/core/ports"
	"log"
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
		log.Print("upgrade:", err)
		return err
	}
	defer c.Close()

	issuerDID, err := core.ParseDID(wr.request.Identifier)
	if err != nil {
		return err
	}

	claimUUID, err := uuid.Parse(wr.request.Id)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(Ticker * time.Second)

	for range ticker.C {
		claim, err := wr.claimService.GetByID(context.Background(), issuerDID, claimUUID)
		if err != nil {
			return err
		}
		if claim == nil || claim.IdentityState == nil {
			return err
		}

		state, err := wr.identityService.GetStateByHash(context.Background(), *claim.IdentityState)
		if err != nil {
			return err
		}

		if state.Status == domain.StatusConfirmed {
			if err = c.WriteMessage(websocket.TextMessage, []byte(state.Status)); err != nil {
				log.Println("write:", err)
				break
			}
		}
	}
	return nil
}
