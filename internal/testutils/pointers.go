package testutils

import (
	"net"

	v1core "k8s.io/api/core/v1"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
)

type TestValue interface {
	string | int32 | bool | uint32 | net.IP | v1core.Protocol | utils.Base64String
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
