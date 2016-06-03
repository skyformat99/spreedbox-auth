package owncloud

import (
	"golang.struktur.de/spreedbox/spreedbox-auth/auth/claim"
)

const (
	DisplayNameClaimID     = "oc/display_name"
	IsAdminClaimID         = "oc/is_admin"
	IsSpreedmeAdminClaimID = "oc/is_spreedme_admin"
)

var IsAdminClaim = claim.New(IsAdminClaimID, true)
