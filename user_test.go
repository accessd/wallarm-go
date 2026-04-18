package wallarm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserRead(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/objects/user", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"body": [{
				"id": 1,
				"email": "user@example.com",
				"realname": "Test User",
				"permissions": ["admin"],
				"clientid": 8649,
				"enabled": true
			}]
		}`)
	})

	res, err := client.UserRead(&UserGet{
		Limit:  1,
		Filter: &UserFilter{},
	})
	assert.NoError(t, err)
	assert.Len(t, res.Body, 1)
	assert.Equal(t, "user@example.com", res.Body[0].Email)
}

func TestUserCreate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/objects/user/create", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"body": {
				"id": 2,
				"email": "new@example.com",
				"realname": "New User",
				"clientid": 8649,
				"enabled": true,
				"permissions": ["admin"]
			}
		}`)
	})

	res, err := client.UserCreate(&UserCreate{
		Email:       "new@example.com",
		Realname:    "New User",
		Permissions: []string{"admin"},
		Clientid:    8649,
	})
	assert.NoError(t, err)
	assert.Equal(t, 2, res.Body.ID)
}

func TestUserDelete(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/objects/user/delete", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": null}`)
	})

	err := client.UserDelete(&UserDelete{
		Filter: &UserFilter{ID: 2},
	})
	assert.NoError(t, err)
}

func TestUserUpdate(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/objects/user/update", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status": 200, "body": null}`)
	})

	err := client.UserUpdate(&UserUpdate{
		UserFilter: &UserFilter{ID: 2},
		UserFields: &UserFields{Realname: "Updated Name"},
	})
	assert.NoError(t, err)
}
