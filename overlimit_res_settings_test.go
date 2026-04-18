package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOverlimitResSettingsRead(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/client/8649/rules/overlimit_res_settings", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": {"overlimit_time": 1000}}`)
	})

	res, err := client.OverlimitResSettingsRead(8649)
	assert.NoError(t, err)
	assert.NotNil(t, res)
}

func TestOverlimitResSettingsUpdate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/client/8649/rules/overlimit_res_settings", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": {"overlimit_time": 2000}}`)
	})

	res, err := client.OverlimitResSettingsUpdate(&OverlimitResSettingsParams{OverlimitTime: 2000}, 8649)
	assert.NoError(t, err)
	assert.NotNil(t, res)
}
