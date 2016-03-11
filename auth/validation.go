package auth

import (
	"errors"
	"log"
	"net/http"
	"time"

	"golang.struktur.de/spreedbox/spreedbox-go/bus"
)

type ValidationClient struct {
	Timeout time.Duration
	ec      *bus.EncodedConn
}

func NewValidationClient() *ValidationClient {
	vc := &ValidationClient{
		Timeout: 1 * time.Second,
	}
	return vc
}

func (vc *ValidationClient) Validate(auth string, tokenType string) error {
	if vc.ec == nil {
		log.Println("auth validate without connection")
		return errors.New("temporarily_unavailable")
	}

	request := &ValidateRequest{
		Authorization: auth,
		TokenType:     tokenType,
	}

	reply := &ValidateReply{}
	err := vc.ec.Request(AuthSubjectValidate(), request, reply, vc.Timeout)
	if err == nil {
		if reply.Success {
			return nil
		}
		log.Println("auth validation failed", reply.Error, reply.Message)
		if reply.Error != "" {
			return errors.New(reply.Error)
		}
		return errors.New("server_error")
	}
	log.Println("auth validated failed with error", err)
	return err
}

func (vc *ValidationClient) AccessTokenRequired(r *http.Request) error {
	// TODO(longsleep): Verify request data.
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return errors.New("authorization_missing")
	}

	err := vc.Validate(auth, AccessTokenType)
	if err == nil {
		// Ok.
		return nil
	}
	return err
}

func (vc *ValidationClient) AccessTokenRequiredHandler(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := vc.AccessTokenRequired(r); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func (vc *ValidationClient) Open() (err error) {
	vc.ec, err = bus.EstablishConnection(nil)
	return
}

func (vc *ValidationClient) Close() {
	ec := vc.ec
	if ec != nil {
		vc.ec = nil
		ec.Close()
	}
}
