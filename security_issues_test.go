package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSecurityIssuesRead(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/security_issues", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `[{
			"id": 1,
			"client_id": 8649,
			"severity": "high",
			"state": "open",
			"issue_type": {"id": "xss", "name": "Cross-site Scripting"},
			"host": "example.com"
		}]`)
	})

	res, err := client.GetSecurityIssuesRead(&GetSecurityIssuesRead{
		ClientID: 8649,
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 item, got %d", len(res))
	}
	assert.Equal(t, "high", res[0].Severity)
}
