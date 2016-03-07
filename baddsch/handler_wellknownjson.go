package baddsch

import (
	"bytes"
	"encoding/json"
	"net/http"
	"text/template"
)

// WellknownJSON defines a JSON document to return as HTTP response with
// template interpolation support.
type WellknownJSON struct {
	Data map[string]interface{}
}

// Get is the HTTP response handler for GET requests encoding the
// payload data to JSON with variable interpolation.
func (doc *WellknownJSON) Get(r *http.Request) (int, interface{}, http.Header) {
	b, err := json.MarshalIndent(doc.Data, "", "  ")
	if err != nil {
		return http.StatusInternalServerError, err.Error(), nil
	}

	t, err := template.New("response").Parse(string(b))
	if err != nil {
		return http.StatusInternalServerError, err.Error(), nil
	}

	var response bytes.Buffer
	headerVars := make(map[string]string)
	headerVars["Host"] = r.Host
	t.Execute(&response, headerVars)
	return 200, response.Bytes(), http.Header{"Content-type": {"application/json"}}
}
