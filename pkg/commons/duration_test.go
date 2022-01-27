package commons

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestDuration(t *testing.T) {
	t.Run("test YAMLMarshal", testYAMLMarshal)
	t.Run("test YAMLUnmarshalFromStringWithoutUnits", testYAMLUnmarshalFromStringWithoutUnits)
	t.Run("test YAMLUnmarshalFromString", testYAMLUnmarshalFromString)
}

func testYAMLMarshal(t *testing.T) {
	d1 := Duration(5 * time.Minute)

	yamlBytes, err := yaml.Marshal(d1)
	assert.NoError(t, err)
	assert.NotEmpty(t, string(yamlBytes))

	var d2 Duration
	err = yaml.Unmarshal(yamlBytes, &d2)
	assert.NoError(t, err)
	assert.Equal(t, d1, d2)
}

func testYAMLUnmarshalFromStringWithoutUnits(t *testing.T) {
	v1 := []byte("60000000000")

	var d1 Duration
	err := yaml.Unmarshal(v1, &d1)
	assert.NoError(t, err)
	assert.Equal(t, 1*time.Minute, time.Duration(d1))

	v2 := []byte("6h60000000000")

	var d2 Duration
	err = yaml.Unmarshal(v2, &d2)
	assert.NoError(t, err)
	assert.Equal(t, 6*time.Hour+1*time.Minute, time.Duration(d2))
}

func testYAMLUnmarshalFromString(t *testing.T) {
	v1 := []byte("6m")

	var d1 Duration
	err := yaml.Unmarshal(v1, &d1)
	assert.NoError(t, err)
	assert.Equal(t, 6*time.Minute, time.Duration(d1))

	v2 := []byte("6h6m")

	var d2 Duration
	err = yaml.Unmarshal(v2, &d2)
	assert.NoError(t, err)
	assert.Equal(t, 6*time.Hour+6*time.Minute, time.Duration(d2))
}
