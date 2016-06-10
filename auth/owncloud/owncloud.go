package owncloud

import (
	"golang.struktur.de/spreedbox/spreedbox-auth/auth/claim"
)

const (
	IsAdminClaimID         = "oc/is_admin"
	IsSpreedmeAdminClaimID = "oc/is_spreedme_admin"
)

var IsAdminClaim = claim.New(IsAdminClaimID, true)
