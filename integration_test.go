package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

const integrationResp = `{
	"body": {
		"result": "success",
		"object": {
			"id": 100,
			"active": true,
			"name": "test",
			"type": "slack",
			"events": [{"event": "system", "active": true}]
		}
	}
}`

func TestIntegrationCreate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, integrationResp)
	})

	events := []IntegrationEvents{{Event: "system", Active: true}}
	res, err := client.IntegrationCreate(&IntegrationCreate{
		Name:   "test",
		Active: true,
		Type:   "slack",
		Events: &events,
	})
	assert.NoError(t, err)
	assert.Equal(t, 100, res.Body.ID)
}

func TestIntegrationUpdate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration/100", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, integrationResp)
	})

	events := []IntegrationEvents{{Event: "system", Active: true}}
	res, err := client.IntegrationUpdate(&IntegrationCreate{
		Name:   "test",
		Active: true,
		Events: &events,
	}, 100)
	assert.NoError(t, err)
	assert.Equal(t, 100, res.Body.ID)
}

func TestIntegrationPartialUpdate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration/100", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, integrationResp)
	})

	res, err := client.IntegrationPartialUpdate(100, map[string]interface{}{"active": false})
	assert.NoError(t, err)
	assert.Equal(t, 100, res.Body.ID)
}

func TestIntegrationRead(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"body": {
				"result": "success",
				"object": [{
					"id": 100,
					"active": true,
					"name": "test",
					"type": "slack",
					"events": []
				}]
			}
		}`)
	})

	res, err := client.IntegrationRead(8649, 100)
	assert.NoError(t, err)
	assert.Equal(t, 100, res.ID)
}

func TestIntegrationDelete(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration/100", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200}`)
	})

	err := client.IntegrationDelete(100)
	assert.NoError(t, err)
}

func TestIntegrationWithAPICreate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, integrationResp)
	})

	events := []IntegrationEvents{{Event: "siem", Active: true}}
	res, err := client.IntegrationWithAPICreate(&IntegrationWithAPICreate{
		Name:   "test",
		Active: true,
		Type:   "web_hooks",
		Events: &events,
		Target: &IntegrationWithAPITarget{URL: "https://example.com/hook"},
	})
	assert.NoError(t, err)
	assert.Equal(t, 100, res.Body.ID)
}

func TestIntegrationWithAPIUpdate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration/100", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, integrationResp)
	})

	events := []IntegrationEvents{{Event: "siem", Active: true}}
	res, err := client.IntegrationWithAPIUpdate(&IntegrationWithAPICreate{
		Name:   "test",
		Active: true,
		Events: &events,
		Target: &IntegrationWithAPITarget{URL: "https://example.com/hook"},
	}, 100)
	assert.NoError(t, err)
	assert.Equal(t, 100, res.Body.ID)
}

func TestEmailIntegrationCreate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, integrationResp)
	})

	res, err := client.EmailIntegrationCreate(&EmailIntegrationCreate{
		Name:   "test",
		Active: true,
		Target: []string{"test@example.com"},
	})
	assert.NoError(t, err)
	assert.Equal(t, 100, res.Body.ID)
}

func TestEmailIntegrationUpdate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration/100", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, integrationResp)
	})

	res, err := client.EmailIntegrationUpdate(&EmailIntegrationCreate{
		Name:   "test",
		Active: true,
	}, 100)
	assert.NoError(t, err)
	assert.Equal(t, 100, res.Body.ID)
}

func TestTelegramIntegrationCreate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration/telegram", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, integrationResp)
	})

	res, err := client.TelegramIntegrationCreate(&TelegramIntegrationCreate{
		Name:  "test",
		Token: "123:abc",
	})
	assert.NoError(t, err)
	assert.Equal(t, 100, res.Body.ID)
}

func TestTelegramIntegrationUpdate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/integration/100", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, integrationResp)
	})

	res, err := client.TelegramIntegrationUpdate(&TelegramIntegrationCreate{
		Name:  "test",
		Token: "123:abc",
	}, 100)
	assert.NoError(t, err)
	assert.Equal(t, 100, res.Body.ID)
}
