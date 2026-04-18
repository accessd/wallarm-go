package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCredentialStuffingConfigsRead(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v4/clients/8649/credential_stuffing/configs", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"body": {
				"default": [],
				"custom": [{
					"id": 1,
					"actionid": 10,
					"type": "credentials_point",
					"action": []
				}]
			}
		}`)
	})

	res, err := client.CredentialStuffingConfigsRead(8649)
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "credentials_point", res[0].Type)
}
