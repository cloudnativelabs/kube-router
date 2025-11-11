package utils

import (
	"fmt"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
)

func TestBase64String(t *testing.T) {
	type testStruct struct {
		Password Base64String `yaml:"password"`
	}

	tcs := []struct {
		name          string
		input         []byte
		shouldError   bool
		errorContains string
	}{
		{
			name: "happy path",
			// b64: hello world
			input: []byte(`password: "aGVsbG8gd29ybGQ="`),
		},
		{
			name:          "invalid base64 encoding",
			input:         []byte(`password: "notbase64"`),
			shouldError:   true,
			errorContains: "failed to base64 decode",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(tt *testing.T) {
			var ts testStruct
			err := yaml.Unmarshal(tc.input, &ts)
			fmt.Printf("TS: %+v\n", ts)
			if tc.shouldError {
				assert.ErrorContains(tt, err, tc.errorContains)
			} else {
				assert.NoError(tt, err)
				assert.NotEmpty(tt, ts.Password)
			}
		})
	}
}
