package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPListRead(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/blocklist/clients/8649/groups", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"body": {
				"objects": [{
					"id": 1,
					"client_id": 8649,
					"rule_type": "subnet",
					"list": "block",
					"expired_at": 0,
					"values": ["1.2.3.4/32"]
				}]
			}
		}`)
	})

	res, err := client.DenylistRead(8649)
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "subnet", res[0].RuleType)
}

func TestAllowlistCreate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/blocklist/clients/8649/access_rules", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": null}`)
	})

	err := client.AllowlistCreate(8649, AccessRuleCreateRequest{
		Reason: "test",
		Rules:  []AccessRuleEntry{{RulesType: "ip_range", Values: []string{"5.6.7.8/32"}}},
	})
	assert.NoError(t, err)
}

func TestAllowlistDelete(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/blocklist/clients/8649/groups", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": null}`)
	})

	err := client.AllowlistDelete(8649, []AccessRuleDeleteEntry{{RuleType: "subnet", IDs: []int{1}}})
	assert.NoError(t, err)
}

func TestGraylistCreate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/blocklist/clients/8649/access_rules", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": null}`)
	})

	err := client.GraylistCreate(8649, AccessRuleCreateRequest{
		Reason: "test",
		Rules:  []AccessRuleEntry{{RulesType: "ip_range", Values: []string{"9.8.7.6/32"}}},
	})
	assert.NoError(t, err)
}

func TestGraylistDelete(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/blocklist/clients/8649/groups", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": null}`)
	})

	err := client.GraylistDelete(8649, []AccessRuleDeleteEntry{{RuleType: "subnet", IDs: []int{1}}})
	assert.NoError(t, err)
}

func TestDenylistCreate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/blocklist/clients/8649/access_rules", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": null}`)
	})

	err := client.DenylistCreate(8649, AccessRuleCreateRequest{
		Reason: "test",
		Rules: []AccessRuleEntry{
			{RulesType: "ip_range", Values: []string{"1.2.3.4/32"}},
		},
	})
	assert.NoError(t, err)
}

func TestDenylistDelete(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/blocklist/clients/8649/groups", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": null}`)
	})

	err := client.DenylistDelete(8649, []AccessRuleDeleteEntry{
		{RuleType: "subnet", IDs: []int{1}},
	})
	assert.NoError(t, err)
}
