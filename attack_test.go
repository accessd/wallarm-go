package wallarm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const attackResponseJSON = `{
  "status": 200,
  "body": [
    {
      "id": ["attacks_production_2_202603_v_1", "AM5CP50BU-M_02QxawVC"],
      "attackid": "attacks_production_2_202603_v_1:AM5CP50BU-M_02QxawVC",
      "clientid": 2,
      "domain": "node-data.audit.wallarm.com",
      "poolid": -1,
      "method": "GET",
      "parameter": "GET_filename_value",
      "path": "/log/view",
      "type": "ptrav",
      "first_time": 1774882806,
      "last_time": 1774892699,
      "hits": 111,
      "ip_count": 1,
      "ip_top": [{"ip": "161.97.68.155", "count": 111, "country": "FR"}],
      "country_top": [{"country": "FR", "count": 111}],
      "statuscodes": [200, 404],
      "vulnid": null,
      "threat": 90,
      "target": "server",
      "experimental": null,
      "recheck_status": "unrecheckable",
      "vectors_count": 43,
      "block_status": "monitored",
      "state": null
    },
    {
      "id": ["attacks_production_2_202603_v_1", "BN6DQ61CU-N_13RybyWD"],
      "attackid": "attacks_production_2_202603_v_1:BN6DQ61CU-N_13RybyWD",
      "clientid": 2,
      "domain": "api.audit.wallarm.com",
      "poolid": 5,
      "method": "POST",
      "parameter": "POST_body_value",
      "path": "/v1/login",
      "type": "sqli",
      "first_time": 1774880000,
      "last_time": 1774885000,
      "hits": 42,
      "ip_count": 3,
      "ip_top": [{"ip": "10.0.0.1", "count": 30, "country": "US"}],
      "country_top": [{"country": "US", "count": 30}],
      "statuscodes": [403],
      "vulnid": null,
      "threat": 80,
      "target": "server",
      "experimental": null,
      "recheck_status": "in_progress",
      "vectors_count": 5,
      "block_status": "blocked",
      "state": null
    }
  ]
}`

const attackCountResponseJSON = `{
  "status": 200,
  "body": {
    "attacks": 621,
    "hits": 61818.0,
    "ips": 16
  }
}`

func TestAttackRead(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/objects/attack", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req AttackReadRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, 2, req.Limit)
		assert.Equal(t, "last_time", req.OrderBy)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(attackResponseJSON))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := New(
		UsingBaseURL(server.URL),
		Headers(http.Header{"X-WallarmAPI-Token": []string{"test-token"}}),
	)
	require.NoError(t, err)

	resp, err := client.AttackRead(&AttackReadRequest{
		Filter: &AttackFilter{
			ClientID: []int{2},
			Time:     [][]interface{}{{1774800000, nil}},
		},
		Limit:     2,
		Offset:    0,
		OrderBy:   "last_time",
		OrderDesc: true,
	})
	require.NoError(t, err)

	assert.Equal(t, 200, resp.Status)
	require.Len(t, resp.Body, 2)

	atk := resp.Body[0]
	assert.Equal(t, "attacks_production_2_202603_v_1:AM5CP50BU-M_02QxawVC", atk.AttackID)
	assert.Equal(t, "node-data.audit.wallarm.com", atk.Domain)
	assert.Equal(t, "/log/view", atk.Path)
	assert.Equal(t, "ptrav", atk.Type)
	assert.Equal(t, "GET", atk.Method)
	assert.Equal(t, 111, atk.Hits)
	assert.Equal(t, 1, atk.IPCount)
	assert.Equal(t, 90, atk.Threat)
	assert.Equal(t, 1774882806, atk.FirstTime)
	assert.Equal(t, 1774892699, atk.LastTime)
	assert.Equal(t, 2, atk.ClientID)
	assert.Equal(t, -1, atk.PoolID)
	assert.Equal(t, "server", atk.Target)
	assert.Equal(t, 43, atk.VectorsCount)
	assert.Equal(t, "monitored", atk.BlockStatus)
	assert.Equal(t, "GET_filename_value", atk.Parameter)

	atk2 := resp.Body[1]
	assert.Equal(t, "sqli", atk2.Type)
	assert.Equal(t, "api.audit.wallarm.com", atk2.Domain)
	assert.Equal(t, 42, atk2.Hits)
	assert.Equal(t, "blocked", atk2.BlockStatus)
}

func TestAttackCount(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/objects/attack/count", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(attackCountResponseJSON))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := New(
		UsingBaseURL(server.URL),
		Headers(http.Header{"X-WallarmAPI-Token": []string{"test-token"}}),
	)
	require.NoError(t, err)

	resp, err := client.AttackCount(&AttackCountRequest{
		Filter: &AttackCountFilter{
			ClientID: []int{2},
			Time:     [][]interface{}{{1774800000, nil}},
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 200, resp.Status)
	assert.Equal(t, 621, resp.Body.Attacks)
	assert.Equal(t, 61818.0, resp.Body.Hits)
	assert.Equal(t, 16, resp.Body.IPs)
}
