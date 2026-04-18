package wallarm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContains_Found(t *testing.T) {
	assert.True(t, Contains([]string{"a", "b", "c"}, "b"))
}

func TestContains_NotFound(t *testing.T) {
	assert.False(t, Contains([]string{"a", "b"}, "z"))
}

func TestContains_Empty(t *testing.T) {
	assert.False(t, Contains([]string{}, "a"))
}

func TestIntInList_Found(t *testing.T) {
	assert.True(t, intInList([]int{1, 2, 3}, 2))
}

func TestIntInList_NotFound(t *testing.T) {
	assert.False(t, intInList([]int{1, 2, 3}, 99))
}

func TestIntInList_Empty(t *testing.T) {
	assert.False(t, intInList([]int{}, 1))
}
