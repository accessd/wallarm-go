package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
