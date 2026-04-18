package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHitRead(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/objects/hit", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"body": [{
				"id": ["abc123"],
				"type": "sqli",
				"ip": "1.2.3.4",
				"stamps": [6961],
				"point": ["get", "q"],
				"poolid": 1,
				"request_id": "req-1",
				"domain": "example.com",
				"path": "/api/login"
			}]
		}`)
	})

	state := "open"
	res, err := client.HitRead(&HitReadRequest{
		Limit:  10,
		Filter: &HitFilter{ClientID: 8649, State: &state},
	})
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "sqli", res[0].Type)
	assert.Equal(t, "example.com", res[0].Domain)
}
