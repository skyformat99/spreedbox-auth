package baddsch

import (
	"fmt"
	"log"

	"golang.struktur.de/spreedbox/spreedbox-auth/auth"
	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch"
	"golang.struktur.de/spreedbox/spreedbox-auth/provider/owncloud"

	"github.com/gorilla/mux"
	"github.com/strukturag/phoenix"
	"github.com/strukturag/sloth"
	"golang.struktur.de/spreedbox/spreedbox-go/bus"
)

type Server struct {
	ec  *bus.EncodedConn
	api *baddsch.APIv1
}

func NewServer() (*Server, error) {
	s := &Server{}

	return s, nil
}

func (s *Server) Serve(runtime phoenix.Runtime) (err error) {
	// Authentication provider.
	var authProvider baddsch.AuthProvider
	switch runtime.GetStringDefault("provider", "provider", "") {
	case "owncloud":
		if owncloudURL, err := runtime.GetString("provider", "owncloudURL"); err == nil {
			if owncloudURL == "" {
				return fmt.Errorf("owncloudURL cannot be empty")
			}
			conf := owncloud.NewProviderConfig(
				runtime.GetBoolDefault("provider", "owncloudSkipSSLValidation", owncloud.DefaultProviderSkipSSLValidation),
				runtime.GetIntDefault("provider", "owncloudConnectionPoolSize", owncloud.DefaultProviderPoolSize),
			)
			authProvider, _ = owncloud.NewProvider(owncloudURL, conf)
		} else {
			return err
		}
	default:
		return fmt.Errorf("provider required")
	}

	log.Println("connecting events")
	s.ec, err = bus.EstablishConnection(nil)
	if err != nil {
		return err
	}
	defer s.ec.Close()

	// HTTP listener support.
	router := mux.NewRouter()
	if _, err := runtime.GetString("http", "listen"); err == nil {
		runtime.DefaultHTTPHandler(router)
	}

	// Add HTTP API.
	rest := sloth.NewAPI()
	rest.SetMux(router.PathPrefix("/api/v1/").Subrouter())
	s.api, err = baddsch.NewAPIv1(rest, runtime, authProvider)
	if err != nil {
		return err
	}

	// Add NATS API.
	s.ec.Subscribe(auth.AuthSubjectValidate(), s.validate)
	log.Println("events connected and subscribed")

	return runtime.Start()
}

func (s *Server) validate(subject, reply string, msg *auth.ValidateRequest) {
	log.Println("validate", subject, reply)

	if reply != "" {
		request := &baddsch.ValidationRequest{
			Options: &baddsch.ValidationRequestOptions{
				Authorization: msg.Authorization,
			},
			TokenType: msg.TokenType,
		}
		err, errDescription := request.Validate(s.api.ValidateDocument)
		replyData := &auth.ValidateReply{}
		if err == nil {
			replyData.Success = true
		} else {
			log.Println("validate failed", subject, reply, err, errDescription)
			replyData.Error = err.Error()
			replyData.Message = errDescription
		}

		s.ec.Publish(reply, replyData)
	}
}
