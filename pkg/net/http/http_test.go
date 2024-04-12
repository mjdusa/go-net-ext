package http_test

import (
	"fmt"
	"testing"

	"github.com/mjdusa/go-net-ext/pkg/net/http"
	"github.com/stretchr/testify/assert"
)

func TestWrapError(t *testing.T) {
	err := fmt.Errorf("TestWrapError: %d", 99)
	msg := "message"

	expected := fmt.Errorf("%s: %w", msg, err)

	actual := http.WrapError(msg, err)

	assert.Equal(t, expected, actual)
}
