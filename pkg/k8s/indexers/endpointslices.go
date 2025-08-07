package indexers

import (
	"fmt"

	discoveryv1 "k8s.io/api/discovery/v1"
)

// ServiceNameIndex is the name for our custom index.
const ServiceNameIndex = "service-name"

// ServiceNameIndexFunc creates an index key based on an EndpointSlice's parent Service.
// The key is in the format "<namespace>/<service-name>".
func ServiceNameIndexFunc(obj interface{}) ([]string, error) {
	slice, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return []string{}, nil
	}

	serviceName, ok := slice.Labels[discoveryv1.LabelServiceName]
	if !ok || serviceName == "" {
		// This slice is not associated with a Service, so we can't index it.
		return []string{}, nil
	}

	return []string{fmt.Sprintf("%s/%s", slice.Namespace, serviceName)}, nil
}
