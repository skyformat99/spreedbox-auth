package baddsch

import (
	"errors"
	"log"
	"net/http"
)

type RevocateDocument struct {
	ValidateDocument *ValidateDocument
}

func (doc *RevocateDocument) Post(r *http.Request) (int, interface{}, http.Header) {
	log.Println("recovation http")
	rr, err := NewRevocationRequest(r)
	if err != nil {
		return http.StatusBadRequest, err.Error(), nil
	}
	return rr.Response(doc)
}

type RevocationRequest struct {
	ValidationRequest *ValidationRequest `schema:"-"`
	Token             string             `schema:"token"`
	TokenType         string             `schema:"token_type"`
}

func NewRevocationRequest(r *http.Request) (*RevocationRequest, error) {
	rr := &RevocationRequest{}
	if err := DecodeRequestSchema(rr, r.Form); err != nil {
		return nil, err
	}

	vr, err := NewValidationRequest(r)
	if err != nil {
		return nil, err
	}
	vr.TokenType = "" // Handle this ourselves.
	rr.ValidationRequest = vr

	return rr, nil
}

func (rr *RevocationRequest) Revocate(doc *RevocateDocument) (error, string) {
	switch rr.TokenType {
	case "access_token":
		fallthrough
	case "":
		fallthrough
	case "id_token":
	default:
		return errors.New("unsupported_token_type"), "Unsupported token_type"
	}

	token := rr.ValidationRequest.Token
	if token == nil {
		return errors.New("access_denied"), "No token"
	}

	// Add token to blacklist.
	doc.ValidateDocument.Blacklist.SetIfAbsent(token.Raw, true)

	return nil, ""
}

func (rr *RevocationRequest) Response(doc *RevocateDocument) (int, interface{}, http.Header) {
	if err, errDescription := rr.ValidationRequest.Validate(doc.ValidateDocument); err != nil {
		log.Println("revocate validate failed http", err, errDescription)

		return http.StatusBadRequest, err.Error(), nil
	}

	if err, errDescription := rr.Revocate(doc); err != nil {
		log.Println("revocate failed http", err, errDescription)
		return http.StatusServiceUnavailable, "", nil
	}

	return http.StatusOK, "", nil
}
