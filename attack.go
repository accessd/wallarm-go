package wallarm

import "encoding/json"

type (
	Attack interface {
		AttackRead(body *AttackReadRequest) (*AttackReadResp, error)
		AttackCount(body *AttackCountRequest) (*AttackCountResp, error)
	}

	AttackReadRequest struct {
		Filter    *AttackFilter `json:"filter"`
		Limit     int           `json:"limit"`
		Offset    int           `json:"offset"`
		OrderBy   string        `json:"order_by"`
		OrderDesc bool          `json:"order_desc"`
	}

	AttackFilter struct {
		ClientID        []int           `json:"clientid,omitempty"`
		Time            [][]interface{} `json:"time,omitempty"`
		Type            []string        `json:"type,omitempty"`
		NotType         []string        `json:"!type,omitempty"`
		Domain          []string        `json:"domain,omitempty"`
		Path            []string        `json:"path,omitempty"`
		PoolID          []int           `json:"poolid,omitempty"`
		IP              []string        `json:"ip,omitempty"`
		AttackID        []string        `json:"attackid,omitempty"`
		VulnID          []int           `json:"vulnid,omitempty"`
		NotVulnID       interface{}     `json:"!vulnid,omitempty"`
		Experimental    *bool           `json:"experimental,omitempty"`
		NotExperimental *bool           `json:"!experimental,omitempty"`
		Threat          []int           `json:"threat,omitempty"`
		StatusCode      []int           `json:"statuscode,omitempty"`
		Method          []string        `json:"method,omitempty"`
	}

	AttackBody struct {
		ID            []string    `json:"id"`
		AttackID      string      `json:"attackid"`
		ClientID      int         `json:"clientid"`
		Domain        string      `json:"domain"`
		PoolID        int         `json:"poolid"`
		Method        string      `json:"method"`
		Parameter     string      `json:"parameter"`
		Path          string      `json:"path"`
		Type          string      `json:"type"`
		FirstTime     int         `json:"first_time"`
		LastTime      int         `json:"last_time"`
		Hits          int         `json:"hits"`
		HitsCount     int         `json:"hits_count_by_filter"`
		IPCount       int         `json:"ip_count"`
		IPCountFilter int         `json:"ip_count_by_filter"`
		StatusCodes   []int       `json:"statuscodes"`
		Threat        int         `json:"threat"`
		VulnID        interface{} `json:"vulnid"`
		Target        string      `json:"target"`
		VectorsCount  int         `json:"vectors_count"`
		BlockStatus   string      `json:"block_status"`

		IPTop []struct {
			IP      string `json:"ip"`
			Count   int    `json:"count"`
			Country string `json:"country"`
		} `json:"ip_top"`

		CountryTop []struct {
			Country string `json:"country"`
			Count   int    `json:"count"`
		} `json:"country_top"`

		RecheckStatus string      `json:"recheck_status"`
		Experimental  interface{} `json:"experimental"`
		State         interface{} `json:"state"`
	}

	AttackReadResp struct {
		Status int          `json:"status"`
		Body   []AttackBody `json:"body"`
	}

	AttackCountRequest struct {
		Filter *AttackCountFilter `json:"filter"`
	}

	AttackCountFilter struct {
		ClientID   []int           `json:"clientid,omitempty"`
		Time       [][]interface{} `json:"time,omitempty"`
		AttackID   []string        `json:"attackid,omitempty"`
		StatusCode []int           `json:"statuscode,omitempty"`
		IP         []string        `json:"ip,omitempty"`
		ID         []string        `json:"id,omitempty"`
	}

	AttackCountResp struct {
		Status int `json:"status"`
		Body   struct {
			Attacks int     `json:"attacks"`
			Hits    float64 `json:"hits"`
			IPs     int     `json:"ips"`
		} `json:"body"`
	}
)

func (api *api) AttackRead(body *AttackReadRequest) (*AttackReadResp, error) {
	uri := "/v1/objects/attack"
	respBody, err := api.makeRequest("POST", uri, "attack", body)
	if err != nil {
		return nil, err
	}
	var resp AttackReadResp
	if err = json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (api *api) AttackCount(body *AttackCountRequest) (*AttackCountResp, error) {
	uri := "/v1/objects/attack/count"
	respBody, err := api.makeRequest("POST", uri, "attack", body)
	if err != nil {
		return nil, err
	}
	var resp AttackCountResp
	if err = json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
