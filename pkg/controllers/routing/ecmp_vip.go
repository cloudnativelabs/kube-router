package routing

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang/glog"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"strings"
)

// bgpAdvertiseVIP advertises the service vip (cluster ip or load balancer ip or external IP) the configured peers
func (nrc *NetworkRoutingController) bgpAdvertiseVIP(vip string) error {

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(nrc.nodeIP.String()),
	}

	glog.V(2).Infof("Advertising route: '%s/%s via %s' to peers", vip, strconv.Itoa(32), nrc.nodeIP.String())

	_, err := nrc.bgpServer.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(32),
		vip), false, attrs, time.Now(), false)})

	return err
}

// bgpWithdrawVIP  unadvertises the service vip
func (nrc *NetworkRoutingController) bgpWithdrawVIP(vip string) error {
	glog.V(2).Infof("Withdrawing route: '%s/%s via %s' to peers", vip, strconv.Itoa(32), nrc.nodeIP.String())

	pathList := []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(32),
		vip), true, nil, time.Now(), false)}

	err := nrc.bgpServer.DeletePath([]byte(nil), 0, "", pathList)

	return err
}

func (nrc *NetworkRoutingController) advertiseVIPs(vips []string) {
	for _, vip := range vips {
		err := nrc.bgpAdvertiseVIP(vip)
		if err != nil {
			glog.Errorf("error advertising IP: %q, error: %v", vip, err)
		}
	}
}

func (nrc *NetworkRoutingController) withdrawVIPs(vips []string) {
	for _, vip := range vips {
		err := nrc.bgpWithdrawVIP(vip)
		if err != nil {
			glog.Errorf("error withdrawing IP: %q, error: %v", vip, err)
		}
	}
}

func (nrc *NetworkRoutingController) newServiceEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nrc.OnServiceCreate(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nrc.OnServiceUpdate(newObj, oldObj)
		},
		DeleteFunc: func(obj interface{}) {
			nrc.OnServiceDelete(obj)
		},
	}
}

func getServiceObject(obj interface{}) (svc *v1core.Service) {
	if svc, _ = obj.(*v1core.Service); svc == nil {
		glog.Errorf("cache indexer returned obj that is not type *v1.Service")
	}
	return
}

func (nrc *NetworkRoutingController) handleServiceUpdate(svc *v1core.Service) {
	if !nrc.bgpServerStarted {
		glog.V(3).Infof("Skipping update to service: %s/%s, controller still performing bootup full-sync", svc.Namespace, svc.Name)
		return
	}

	toAdvertise, toWithdraw, err := nrc.getVIPsForService(svc, true)
	if err != nil {
		glog.Errorf("error getting routes for service: %s, err: %s", svc.Name, err)
		return
	}

	// update export policies so that new VIP's gets addedd to clusteripprefixsit and vip gets advertised to peers
	err = nrc.AddPolicies()
	if err != nil {
		glog.Errorf("Error adding BGP policies: %s", err.Error())
	}

	nrc.advertiseVIPs(toAdvertise)
	nrc.withdrawVIPs(toWithdraw)
}

func (nrc *NetworkRoutingController) tryHandleServiceUpdate(obj interface{}, logMsgFormat string) {
	if svc := getServiceObject(obj); svc != nil {
		glog.V(1).Infof(logMsgFormat, svc.Namespace, svc.Name)
		nrc.handleServiceUpdate(svc)
	}
}

// OnServiceCreate handles new service create event from the kubernetes API server
func (nrc *NetworkRoutingController) OnServiceCreate(obj interface{}) {
	nrc.tryHandleServiceUpdate(obj, "Received new service: %s/%s from watch API")
}

// OnServiceUpdate handles the service relates updates from the kubernetes API server
func (nrc *NetworkRoutingController) OnServiceUpdate(objNew interface{}, objOld interface{}) {
	nrc.tryHandleServiceUpdate(objNew, "Received update on service: %s/%s from watch API")

	nrc.withdrawVIPs(nrc.getWithdraw(getServiceObject(objOld), getServiceObject(objNew)))
}

func (nrc *NetworkRoutingController) getWithdraw(svcOld, svcNew *v1core.Service) (out []string) {
	if svcOld != nil && svcNew != nil {
		out = getMissingPrevGen(nrc.getExternalIps(svcOld), nrc.getExternalIps(svcNew))
	}
	return
}

func getMissingPrevGen(old, new []string) (withdrawIPs []string) {
	lookIn := " " + strings.Join(new, " ") + " "
	for _, s := range old {
		if !strings.Contains(lookIn, " "+s+" ") {
			withdrawIPs = append(withdrawIPs, s)
		}
	}
	return
}

// OnServiceDelete handles the service delete updates from the kubernetes API server
func (nrc *NetworkRoutingController) OnServiceDelete(obj interface{}) {
	nrc.tryHandleServiceUpdate(obj, "Received event to delete service: %s/%s from watch API")
}

func (nrc *NetworkRoutingController) newEndpointsEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nrc.OnEndpointsAdd(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nrc.OnEndpointsUpdate(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			// don't do anything if an endpoints resource is deleted since
			// the service delete event handles route withdrawls
			return
		},
	}
}

// OnEndpointsAdd handles endpoint add events from apiserver
// This method calls OnEndpointsUpdate with the addition of updating BGP export policies
// Calling AddPolicies here covers the edge case where AddPolicies fails in
// OnServiceUpdate because the corresponding Endpoint resource for the
// Service was not created yet.
func (nrc *NetworkRoutingController) OnEndpointsAdd(obj interface{}) {
	if !nrc.bgpServerStarted {
		glog.V(3).Info("Skipping OnAdd event to endpoint, controller still performing bootup full-sync")
		return
	}

	err := nrc.AddPolicies()
	if err != nil {
		glog.Errorf("error adding BGP policies: %s", err)
	}

	nrc.OnEndpointsUpdate(obj)
}

// OnEndpointsUpdate handles the endpoint updates from the kubernetes API server
func (nrc *NetworkRoutingController) OnEndpointsUpdate(obj interface{}) {
	ep, ok := obj.(*v1core.Endpoints)
	if !ok {
		glog.Errorf("cache indexer returned obj that is not type *v1.Endpoints")
		return
	}

	if isEndpointsForLeaderElection(ep) {
		return
	}

	glog.V(1).Infof("Received update to endpoint: %s/%s from watch API", ep.Namespace, ep.Name)
	if !nrc.bgpServerStarted {
		glog.V(3).Infof("Skipping update to endpoint: %s/%s, controller still performing bootup full-sync", ep.Namespace, ep.Name)
		return
	}

	svc, err := nrc.serviceForEndpoints(ep)
	if err != nil {
		glog.Errorf("failed to convert endpoints resource to service: %s", err)
		return
	}

	nrc.tryHandleServiceUpdate(svc, "Updating service %s/%s triggered by endpoint update event")
}

func (nrc *NetworkRoutingController) serviceForEndpoints(ep *v1core.Endpoints) (interface{}, error) {
	key, err := cache.MetaNamespaceKeyFunc(ep)
	if err != nil {
		return nil, err
	}

	item, exists, err := nrc.svcLister.GetByKey(key)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("service resource doesn't exist for endpoints: %q", ep.Name)
	}

	return item, nil
}

func (nrc *NetworkRoutingController) getClusterIp(svc *v1core.Service) string {
	clusterIp := ""
	if svc.Spec.Type == "ClusterIP" || svc.Spec.Type == "NodePort" || svc.Spec.Type == "LoadBalancer" {

		// skip headless services
		if svc.Spec.ClusterIP != "None" && svc.Spec.ClusterIP != "" {
			clusterIp = svc.Spec.ClusterIP
		}
	}
	return clusterIp
}

func (nrc *NetworkRoutingController) getExternalIps(svc *v1core.Service) []string {
	externalIpList := make([]string, 0)
	if svc.Spec.Type == "ClusterIP" || svc.Spec.Type == "NodePort" {

		// skip headless services
		if svc.Spec.ClusterIP != "None" && svc.Spec.ClusterIP != "" {
			externalIpList = append(externalIpList, svc.Spec.ExternalIPs...)
		}
	}
	return externalIpList
}

func (nrc *NetworkRoutingController) getLoadBalancerIps(svc *v1core.Service) []string {
	loadBalancerIpList := make([]string, 0)
	if svc.Spec.Type == "LoadBalancer" {
		// skip headless services
		if svc.Spec.ClusterIP != "None" && svc.Spec.ClusterIP != "" {
			for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
				if len(lbIngress.IP) > 0 {
					loadBalancerIpList = append(loadBalancerIpList, lbIngress.IP)
				}
			}
		}
	}
	return loadBalancerIpList
}

func (nrc *NetworkRoutingController) getAllVIPs() ([]string, []string, error) {
	return nrc.getVIPs(false)
}

func (nrc *NetworkRoutingController) getActiveVIPs() ([]string, []string, error) {
	return nrc.getVIPs(true)
}

func (nrc *NetworkRoutingController) getVIPs(onlyActiveEndpoints bool) ([]string, []string, error) {
	toAdvertiseList := make([]string, 0)
	toWithdrawList := make([]string, 0)

	for _, obj := range nrc.svcLister.List() {
		svc := obj.(*v1core.Service)

		toAdvertise, toWithdraw, err := nrc.getVIPsForService(svc, onlyActiveEndpoints)
		if err != nil {
			return nil, nil, err
		}

		if len(toAdvertise) > 0 {
			toAdvertiseList = append(toAdvertiseList, toAdvertise...)
		}

		if len(toWithdraw) > 0 {
			toWithdrawList = append(toWithdrawList, toWithdraw...)
		}
	}

	return toAdvertiseList, toWithdrawList, nil
}

func (nrc *NetworkRoutingController) shouldAdvertiseService(svc *v1core.Service, annotation string, defaultValue bool) bool {
	returnValue := defaultValue
	stringValue, exists := svc.Annotations[annotation]
	if exists {
		// Service annotations overrides defaults.
		returnValue, _ = strconv.ParseBool(stringValue)
	}
	return returnValue
}

func (nrc *NetworkRoutingController) getVIPsForService(svc *v1core.Service, onlyActiveEndpoints bool) ([]string, []string, error) {
	ipList := make([]string, 0)
	var err error

	nodeHasEndpoints := true
	if onlyActiveEndpoints {
		_, isLocal := svc.Annotations[svcLocalAnnotation]
		if isLocal || svc.Spec.ExternalTrafficPolicy == v1core.ServiceExternalTrafficPolicyTypeLocal {
			nodeHasEndpoints, err = nrc.nodeHasEndpointsForService(svc)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	if nrc.shouldAdvertiseService(svc, svcAdvertiseClusterAnnotation, nrc.advertiseClusterIP) {
		clusterIp := nrc.getClusterIp(svc)
		if clusterIp != "" {
			ipList = append(ipList, clusterIp)
		}
	}

	if nrc.shouldAdvertiseService(svc, svcAdvertiseExternalAnnotation, nrc.advertiseExternalIP) {
		ipList = append(ipList, nrc.getExternalIps(svc)...)
	}

	// Deprecated: Use service.advertise.loadbalancer=false instead of service.skiplbips.
	_, skiplbips := svc.Annotations[svcSkipLbIpsAnnotation]
	advertiseLoadBalancer := nrc.shouldAdvertiseService(svc, svcAdvertiseLoadBalancerAnnotation, nrc.advertiseLoadBalancerIP)
	if advertiseLoadBalancer && !skiplbips {
		ipList = append(ipList, nrc.getLoadBalancerIps(svc)...)
	}

	if !nodeHasEndpoints {
		return nil, ipList, nil
	}

	return ipList, nil, nil
}

func isEndpointsForLeaderElection(ep *v1core.Endpoints) bool {
	_, isLeaderElection := ep.Annotations[LeaderElectionRecordAnnotationKey]
	return isLeaderElection
}

// nodeHasEndpointsForService will get the corresponding Endpoints resource for a given Service
// return true if any endpoint addresses has NodeName matching the node name of the route controller
func (nrc *NetworkRoutingController) nodeHasEndpointsForService(svc *v1core.Service) (bool, error) {
	// listers for endpoints and services should use the same keys since
	// endpoint and service resources share the same object name and namespace
	key, err := cache.MetaNamespaceKeyFunc(svc)
	if err != nil {
		return false, err
	}
	item, exists, err := nrc.epLister.GetByKey(key)
	if err != nil {
		return false, err
	}

	if !exists {
		return false, fmt.Errorf("endpoint resource doesn't exist for service: %q", svc.Name)
	}

	ep, ok := item.(*v1core.Endpoints)
	if !ok {
		return false, errors.New("failed to convert cache item to Endpoints type")
	}

	for _, subset := range ep.Subsets {
		for _, address := range subset.Addresses {
			if *address.NodeName == nrc.nodeName {
				return true, nil
			}
		}
	}

	return false, nil
}
