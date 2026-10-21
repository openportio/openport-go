package openport

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubstitutePort(t *testing.T) {
	assert.Equal(t, "ssh root@localhost -p 1234", substitutePort("ssh root@localhost -p $port", 1234))
	assert.Equal(t, "curl http://localhost:1234/x", substitutePort("curl http://localhost:${port}/x", 1234))
	assert.Equal(t, "1234 1234", substitutePort("${port} $port", 1234))
	assert.Equal(t, "no placeholders", substitutePort("no placeholders", 1234))
}
