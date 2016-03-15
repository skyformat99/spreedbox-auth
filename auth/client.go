package auth

import (
	"errors"
	"log"
	"time"

	"golang.struktur.de/spreedbox/spreedbox-go/bus"
)

type Client struct {
	Timeout time.Duration
	ec      *bus.EncodedConn
}

func NewClient() *Client {
	vc := &Client{
		Timeout: 1 * time.Second,
	}
	return vc
}

func (vc *Client) DoValidateRequest(request *ValidateRequest) error {
	if vc.ec == nil {
		log.Println("auth validate without connection")
		return errors.New("temporarily_unavailable")
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

func (vc *Client) Validator() *Validator {
	return &Validator{
		Client: vc,
	}
}

func (vc *Client) Open() (err error) {
	vc.ec, err = bus.EstablishConnection(nil)
	return
}

func (vc *Client) Close() {
	ec := vc.ec
	if ec != nil {
		vc.ec = nil
		ec.Close()
	}
}
