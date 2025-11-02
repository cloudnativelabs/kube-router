package testutils

import (
	"net"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
)

type TestValue interface {
	string | uint32 | net.IP | utils.Base64String
}

func ValToPtr[V TestValue](v V) *V {
	return &v
}

func PtrToVal[V TestValue](v *V) V {
	if v == nil {
		return *new(V)
	}
	return *v
}
