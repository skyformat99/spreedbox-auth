package auth

import (
	"fmt"

	"golang.struktur.de/spreedbox/spreedbox-auth/auth/claim"
	"golang.struktur.de/spreedbox/spreedbox-auth/auth/owncloud"
)

const (
	BUS_AUTH_SUBJECT = "auth"
	AccessTokenType  = "access_token"
	IDTokenType      = "id_token"

	SpreedboxScopeID       = "spreedbox"
	SpreedboxIsUserClaimID = "spreedbox/is_user"
)

var IsAdminClaim = owncloud.IsAdminClaim
var IsUserClaim = claim.New(SpreedboxIsUserClaimID, true)

func AuthSubjectValidate() string {
	return fmt.Sprintf("%s.validate", BUS_AUTH_SUBJECT)
}

type ValidateRequest struct {
	Authorization  string                 `json:"authorization"`
	RequiredClaims map[string]interface{} `json:"required_claims,omitempty"`
	TokenType      string                 `json:"token_type,omitempty"`
}

type ValidateReply struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}
