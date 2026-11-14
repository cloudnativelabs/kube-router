package utils

import (
	discoveryv1 "k8s.io/api/discovery/v1"
)

// EndpointIsReadyOrServing returns true when an EndpointSlice endpoint should receive service traffic.
//
// Unlike the legacy Endpoints API, EndpointSlices keep ready and not-ready endpoints in the same list, so
// consumers must inspect the endpoint conditions. An endpoint is usable when it is ready or when it is still
// serving, which allows terminating endpoints to keep serving traffic during a rolling update. Per the
// EndpointSlice API, a nil ready or serving condition is interpreted as true.
func EndpointIsReadyOrServing(ep discoveryv1.Endpoint) bool {
	ready := ep.Conditions.Ready == nil || *ep.Conditions.Ready
	serving := ep.Conditions.Serving == nil || *ep.Conditions.Serving
	return ready || serving
}
