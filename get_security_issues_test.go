package wallarm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSecurityIssuesRead(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/security_issues", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		var req GetSecurityIssuesRead
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, 2, req.ClientID)
		assert.Equal(t, "test-token", req.Token)
		require.NotNil(t, req.Filter)
		assert.Equal(t, []string{"open"}, req.Filter.State)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":40450,"client_id":2,"severity":"critical","state":"open","volume":1,"name":"Apache HTTP Server 2.4.49","created_at":1743520000,"discovered_at":1743520100,"discovered_by":"wallarm_soc","discovered_by_display_name":"Wallarm SOC","url":"https://api.example.com/","host":"api.example.com","path":"/","parameter_display_name":"","parameter_position":"","parameter_name":"","http_method":"GET","aasm_template":"vuln_soft.apache","mitigations":{"vpatch":{"rule_id":123}},"issue_type":{"id":"vuln_soft","name":"Vulnerable software"},"owasp":[],"tags":[],"incident":false,"verified":false}]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := New(
		UsingBaseURL(server.URL),
		Headers(http.Header{"X-WallarmAPI-Token": []string{"test-token"}}),
	)
	require.NoError(t, err)

	resp, err := client.GetSecurityIssuesRead(&GetSecurityIssuesRead{
		securityIssuesRequestBase: securityIssuesRequestBase{ClientID: 2},
		Limit:                     1,
		Filter:                    &GetSecurityIssuesFilter{State: []string{"open"}},
	})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, 40450, resp[0].ID)
	assert.Equal(t, "api.example.com", resp[0].Host)
	assert.Equal(t, "vuln_soft", resp[0].IssueType.ID)
}

func TestGetSecurityIssuesCount(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/security_issues/count", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		var req GetSecurityIssuesCountRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, 2, req.ClientID)
		assert.Equal(t, "test-token", req.Token)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"count":312}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := New(
		UsingBaseURL(server.URL),
		Headers(http.Header{"X-WallarmAPI-Token": []string{"test-token"}}),
	)
	require.NoError(t, err)

	resp, err := client.GetSecurityIssuesCount(&GetSecurityIssuesCountRequest{
		securityIssuesRequestBase: securityIssuesRequestBase{ClientID: 2},
		Filter:                    &GetSecurityIssuesFilter{},
	})
	require.NoError(t, err)
	assert.Equal(t, 312, resp.Count)
}

func TestGetSecurityIssueGroups(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/security_issues/groups", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		var req GetSecurityIssueGroupsRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, 2, req.ClientID)
		assert.Equal(t, "test-token", req.Token)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"group_id":"grp-1","title":"Apache HTTP Server 2.4.49","severity":"critical","discovered_by":"wallarm_soc","discovered_by_display_name":"Wallarm SOC","issue_type":{"id":"vuln_soft","name":"Vulnerable software"},"security_issues_count":14,"states":{"open":10,"closed":3,"marked_false":1},"owasp":[],"hosts_count":4,"first_host":"api.example.com","client_id":2,"tags":[]}]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := New(
		UsingBaseURL(server.URL),
		Headers(http.Header{"X-WallarmAPI-Token": []string{"test-token"}}),
	)
	require.NoError(t, err)

	resp, err := client.GetSecurityIssueGroups(&GetSecurityIssueGroupsRequest{
		securityIssuesRequestBase: securityIssuesRequestBase{ClientID: 2},
		Limit:                     1,
	})
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "grp-1", resp[0].GroupID)
	assert.Equal(t, 10, resp[0].States.Open)
}

func TestGetSecurityIssueGroupsCount(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/security_issues/groups_count", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		var req GetSecurityIssuesCountRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, 2, req.ClientID)
		assert.Equal(t, "test-token", req.Token)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"count":240}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := New(
		UsingBaseURL(server.URL),
		Headers(http.Header{"X-WallarmAPI-Token": []string{"test-token"}}),
	)
	require.NoError(t, err)

	resp, err := client.GetSecurityIssueGroupsCount(&GetSecurityIssuesCountRequest{
		securityIssuesRequestBase: securityIssuesRequestBase{ClientID: 2},
	})
	require.NoError(t, err)
	assert.Equal(t, 240, resp.Count)
}

func TestGetSecurityIssue(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/security_issues/40450", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "2", r.URL.Query().Get("client_id"))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":40450,"client_id":2,"severity":"critical","state":"open","volume":1,"name":"Apache HTTP Server 2.4.49","created_at":1743520000,"discovered_at":1743520100,"discovered_by":"wallarm_soc","discovered_by_display_name":"Wallarm SOC","url":"https://api.example.com/","host":"api.example.com","path":"/","parameter_display_name":"","parameter_position":"","parameter_name":"","http_method":"GET","aasm_template":"vuln_soft.apache","mitigations":{"vpatch":{"rule_id":123}},"issue_type":{"id":"vuln_soft","name":"Vulnerable software"},"owasp":[],"tags":[],"incident":false,"verified":false,"description":"detail","references":["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],"mitigation":"upgrade","risk_info":{"cvss":9.8},"status_history":[{"state":"open"}],"known_cves":[{"name":"CVE-2021-41773"}]}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := New(
		UsingBaseURL(server.URL),
		Headers(http.Header{"X-WallarmAPI-Token": []string{"test-token"}}),
	)
	require.NoError(t, err)

	resp, err := client.GetSecurityIssue(40450, 2)
	require.NoError(t, err)
	assert.Equal(t, 40450, resp.ID)
	assert.Equal(t, "detail", resp.Description)
	require.Len(t, resp.KnownCVEs, 1)
	assert.Equal(t, "CVE-2021-41773", resp.KnownCVEs[0]["name"])
}
