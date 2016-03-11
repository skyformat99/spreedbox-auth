package auth

import (
	"fmt"
)

const BUS_AUTH_SUBJECT = "auth"

func AuthSubjectValidate() string {
	return fmt.Sprintf("%s.validate", BUS_AUTH_SUBJECT)
}

type ValidateRequest struct {
	Authorization string `json:"authorization"`
	TokenType     string `json:token_type,omitempty"`
}

type ValidateReply struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
