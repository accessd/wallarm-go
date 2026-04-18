package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWallarmModeRead(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/client/8649/rules/wallarm_mode", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"body": {"mode": "monitoring"}
		}`)
	})

	res, err := client.WallarmModeRead(8649)
	assert.NoError(t, err)
	assert.NotNil(t, res)
}

func TestWallarmModeUpdate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/client/8649/rules/wallarm_mode", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"body": {"mode": "block"}
		}`)
	})

	res, err := client.WallarmModeUpdate(&WallarmModeParams{Mode: "block"}, 8649)
	assert.NoError(t, err)
	assert.NotNil(t, res)
}
