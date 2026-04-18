package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientCreate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/objects/client/create", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"body": {
				"id": 12345,
				"uuid": "abc-123",
				"name": "test-tenant",
				"enabled": true,
				"partnerid": 1,
				"partner_uuid": "partner-uuid-1"
			}
		}`)
	})

	res, err := client.ClientCreate(&ClientCreate{
		Name:        "test-tenant",
		PartnerUUID: "partner-uuid-1",
	})
	assert.NoError(t, err)
	assert.Equal(t, 12345, res.Body.ID)
	assert.Equal(t, "test-tenant", res.Body.Name)
}

func TestClientCreate_Error(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/objects/client/create", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":400,"body":"Already exists"}`)
	})

	_, err := client.ClientCreate(&ClientCreate{
		Name:        "test-tenant",
		PartnerUUID: "partner-uuid-1",
	})
	assert.Error(t, err)
}

func TestClientRead(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/objects/client", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"body": [{
				"id": 8649,
				"name": "main-account",
				"enabled": true,
				"partner_uuid": "partner-uuid-1"
			}]
		}`)
	})

	res, err := client.ClientRead(&ClientRead{
		Limit:  1,
		Filter: &ClientReadFilter{},
	})
	assert.NoError(t, err)
	assert.Len(t, res.Body, 1)
	assert.Equal(t, 8649, res.Body[0].ID)
}

func TestClientUpdate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/objects/client/update", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"body": [{
				"id": 8649,
				"name": "updated-name",
				"enabled": true
			}]
		}`)
	})

	enabled := true
	_, err := client.ClientUpdate(&ClientUpdate{
		Filter: &ClientFilter{ID: 8649},
		Fields: &ClientFields{Name: "updated-name", Enabled: &enabled},
	})
	assert.NoError(t, err)
}

func TestClientDelete(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/objects/client/delete", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": [8649]}`)
	})

	res, err := client.ClientDelete(&ClientDelete{
		Filter: &ClientFilter{ID: 8649},
	})
	assert.NoError(t, err)
	assert.Contains(t, res.Body, 8649)
}
