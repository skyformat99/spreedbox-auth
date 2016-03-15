package owncloud

import (
	"golang.struktur.de/spreedbox/spreedbox-auth/auth/claim"
)

const (
	DisplayNameClaimID = "oc/display_name"
	IsAdminClaimID     = "oc/is_admin"
)

var IsAdminClaim = claim.New(IsAdminClaimID, true)
