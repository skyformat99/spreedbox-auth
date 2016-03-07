package baddsch

// APIv1 defines end points of baddsch API version 1.
type APIv1 struct {
}

// NewAPIv1 creates a APIv1 instance return it as API interface
// optionally adding the API resources to a API holder.
func NewAPIv1(holder APIResourceHolder) API {
	api := &APIv1{}
	if holder != nil {
		api.AddResources(holder)
	}
	return api
}

// AddResources adds the resources of this API to the API holder.
func (api *APIv1) AddResources(holder APIResourceHolder) {
	holder.AddResource(&WellknownJSON{map[string]interface{}{
		"owncloud_endpoint":      "https://{{.Host}}/index.php",
		"spreed-webrtc_endpoint": "https://{{.Host}}/webrtc",
	}}, "/well-known/spreed-configuration")
}
