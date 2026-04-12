package netpol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeForComment(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "clean string passes through",
			input: "my-pod-name",
			want:  "my-pod-name",
		},
		{
			name:  "newlines stripped",
			input: "my-pod\n-A INJECT -j DROP\n",
			want:  "my-pod-A INJECT -j DROP",
		},
		{
			name:  "tabs stripped",
			input: "my-pod\tinjected",
			want:  "my-podinjected",
		},
		{
			name:  "carriage return stripped",
			input: "my-pod\rinjected",
			want:  "my-podinjected",
		},
		{
			name:  "null bytes stripped",
			input: "my-pod\x00injected",
			want:  "my-podinjected",
		},
		{
			name:  "normal characters preserved",
			input: "nginx-deployment-7c79f4c9b8-abc12",
			want:  "nginx-deployment-7c79f4c9b8-abc12",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeForComment(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
