package httpex_test

import (
	"fmt"
	"testing"

	"github.com/mjdusa/go-net-ext/pkg/net/httpex"
	"github.com/stretchr/testify/assert"
)

func TestWrapError(t *testing.T) {
	err := fmt.Errorf("TestWrapError: %d", 99)
	msg := "message"

	expected := fmt.Errorf("%s: %w", msg, err)

	actual := httpex.WrapError(msg, err)

	assert.Equal(t, expected, actual)
}
