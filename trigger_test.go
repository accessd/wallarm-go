package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

const triggerResp = `{
	"trigger": {
		"id": 706200,
		"name": "test-trigger",
		"comment": "test",
		"enabled": true,
		"client_id": 8649,
		"template_id": "vector_attack",
		"filters": [
			{"id": "threshold", "values": [{"count": 1, "period": 3600}], "operator": "gt"}
		],
		"actions": [
			{"id": "add_to_graylist", "params": {"lock_time": 14400}}
		],
		"template": {
			"id": "vector_attack",
			"filters": [],
			"threshold": {"operator": "gt", "period": 3600, "count": 3},
			"actions": [{"id": "block_ips", "params": {"lock_time": 3600}}]
		},
		"threshold": {"operator": "gt", "period": 3600, "count": 1},
		"thresholds": [{"operator": "gt", "period": 3600, "count": 1}]
	}
}`

func TestTriggerRead(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/clients/8649/triggers", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"triggers": [{
				"id": 706200,
				"name": "test-trigger",
				"enabled": true,
				"client_id": 8649,
				"filters": [],
				"actions": [{"id": "block_ips"}],
				"template": {"id": "vector_attack", "filters": [], "threshold": {}, "actions": []},
				"threshold": {"operator": "gt", "period": 3600, "count": 1},
				"thresholds": []
			}]
		}`)
	})

	res, err := client.TriggerRead(8649)
	assert.NoError(t, err)
	assert.Len(t, res.Triggers, 1)
	assert.Equal(t, 706200, res.Triggers[0].ID)
	assert.Equal(t, "test-trigger", res.Triggers[0].Name)
}

func TestTriggerCreate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/clients/8649/triggers", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, triggerResp)
	})

	filters := []TriggerFilters{{ID: "threshold", Operator: "gt", Values: []interface{}{map[string]interface{}{"count": 1, "period": 3600}}}}
	actions := []TriggerActions{{ID: "add_to_graylist"}}
	res, err := client.TriggerCreate(&TriggerCreate{
		Trigger: &TriggerParam{
			TemplateID: "vector_attack",
			Filters:    &filters,
			Actions:    &actions,
			Enabled:    true,
			Name:       "test-trigger",
		},
	}, 8649)
	assert.NoError(t, err)
	assert.Equal(t, 706200, res.ID)
}

func TestTriggerDelete(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/clients/8649/triggers/706200", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200}`)
	})

	err := client.TriggerDelete(8649, 706200)
	assert.NoError(t, err)
}

func TestTriggerUpdate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/clients/8649/triggers/706200", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, triggerResp)
	})

	filters := []TriggerFilters{{ID: "threshold", Operator: "gt"}}
	actions := []TriggerActions{{ID: "add_to_graylist"}}
	res, err := client.TriggerUpdate(&TriggerCreate{
		Trigger: &TriggerParam{
			TemplateID: "vector_attack",
			Filters:    &filters,
			Actions:    &actions,
			Enabled:    true,
		},
	}, 8649, 706200)
	assert.NoError(t, err)
	assert.Equal(t, 706200, res.ID)
}
