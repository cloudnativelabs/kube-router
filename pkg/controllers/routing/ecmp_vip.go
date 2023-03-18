package routing

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/exp/maps"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
)

// bgpAdvertiseVIP advertises the service vip (cluster ip or load balancer ip or external IP) the configured peers
func (nrc *NetworkRoutingController) bgpAdvertiseVIP(vip string) error {
	subnet, nh, afiFamily, err := nrc.getBGPRouteInfoForVIP(vip)
	if err != nil {
		return fmt.Errorf("unable to advertise VIP because of: %v", err)
	}

	klog.V(2).Infof("Advertising route: '%s/%d via %s' to peers", vip, subnet, nh)

	a1, _ := anypb.New(&gobgpapi.OriginAttribute{
		Origin: 0,
	})
	a2, _ := anypb.New(&gobgpapi.NextHopAttribute{
		NextHop: nh,
	})
	attrs := []*anypb.Any{a1, a2}
	nlri1, _ := anypb.New(&gobgpapi.IPAddressPrefix{
		Prefix:    vip,
		PrefixLen: subnet,
	})
	_, err = nrc.bgpServer.AddPath(context.Background(), &gobgpapi.AddPathRequest{
		Path: &gobgpapi.Path{
			Family: &gobgpapi.Family{Afi: afiFamily, Safi: gobgpapi.Family_SAFI_UNICAST},
			Nlri:   nlri1,
			Pattrs: attrs,
		},
	})

	if nrc.MetricsEnabled {
		metrics.ControllerBGPadvertisementsSent.WithLabelValues("advertise-vip").Inc()
	}

	return err
}

// bgpWithdrawVIP  un-advertises the service vip
func (nrc *NetworkRoutingController) bgpWithdrawVIP(vip string) error {
	subnet, nh, afiFamily, err := nrc.getBGPRouteInfoForVIP(vip)
	if err != nil {
		return fmt.Errorf("unable to advertise VIP because of: %v", err)
	}

	klog.V(2).Infof("Withdrawing route: '%s/%d via %s' to peers", vip, subnet, nh)

	a1, _ := anypb.New(&gobgpapi.OriginAttribute{
		Origin: 0,
	})
	a2, _ := anypb.New(&gobgpapi.NextHopAttribute{
		NextHop: nh,
	})
	attrs := []*anypb.Any{a1, a2}
	nlri, _ := anypb.New(&gobgpapi.IPAddressPrefix{
		Prefix:    vip,
		PrefixLen: subnet,
	})
	path := gobgpapi.Path{
		Family: &gobgpapi.Family{Afi: afiFamily, Safi: gobgpapi.Family_SAFI_UNICAST},
		Nlri:   nlri,
		Pattrs: attrs,
	}
	err = nrc.bgpServer.DeletePath(context.Background(), &gobgpapi.DeletePathRequest{
		TableType: gobgpapi.TableType_GLOBAL,
		Path:      &path,
	})

	if nrc.MetricsEnabled {
		metrics.ControllerBGPadvertisementsSent.WithLabelValues("withdraw-vip").Inc()
	}

	return err
}

func (nrc *NetworkRoutingController) advertiseVIPs(vips []string) {
	for _, vip := range vips {
		err := nrc.bgpAdvertiseVIP(vip)
		if err != nil {
			klog.Errorf("error advertising IP: %q, error: %v", vip, err)
		}
	}
}

func (nrc *NetworkRoutingController) withdrawVIPs(vips []string) {
	for _, vip := range vips {
		err := nrc.bgpWithdrawVIP(vip)
		if err != nil {
			klog.Errorf("error withdrawing IP: %q, error: %v", vip, err)
		}
	}
}

func (nrc *NetworkRoutingController) newServiceEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nrc.OnServiceCreate(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nrc.OnServiceUpdate(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			nrc.OnServiceDelete(obj)
		},
	}
}

func getServiceObject(obj interface{}) (svc *v1core.Service) {
	if obj == nil {
		return
	}
	if svc, _ = obj.(*v1core.Service); svc == nil {
		klog.Errorf("cache indexer returned obj that is not type *v1.Service")
	}
	return
}

func (nrc *NetworkRoutingController) handleServiceUpdate(svcOld, svcNew *v1core.Service) {
	if !nrc.bgpServerStarted {
		klog.V(3).Infof("Skipping update to service: %s/%s, controller still performing bootup full-sync",
			svcNew.Namespace, svcNew.Name)
		return
	}

	toAdvertise, toWithdraw, err := nrc.getChangedVIPs(svcOld, svcNew, true)
	if err != nil {
		klog.Errorf("error getting routes for services: %s", err)
		return
	}

	// update export policies so that new VIP's gets added to clusteripprefixset and vip gets advertised to peers
	err = nrc.AddPolicies()
	if err != nil {
		klog.Errorf("Error adding BGP policies: %s", err.Error())
	}

	nrc.advertiseVIPs(toAdvertise)
	nrc.withdrawVIPs(toWithdraw)
}

func (nrc *NetworkRoutingController) handleServiceDelete(oldSvc *v1core.Service) {

	if !nrc.bgpServerStarted {
		klog.V(3).Infof("Skipping update to service: %s/%s, controller still performing bootup full-sync",
			oldSvc.Namespace, oldSvc.Name)
		return
	}

	err := nrc.AddPolicies()
	if err != nil {
		klog.Errorf("Error adding BGP policies: %s", err.Error())
	}

	activeVIPs, _, err := nrc.getActiveVIPs()
	if err != nil {
		klog.Errorf("Failed to get active VIP's on service delete event due to: %s", err.Error())
		return
	}
	serviceVIPs := nrc.getAllVIPsForService(oldSvc)
	withdrawVIPs := make([]string, 0)
	for _, serviceVIP := range serviceVIPs {
		// withdraw VIP only if deleted service is the last service using the VIP
		if !utils.SliceContainsString(serviceVIP, activeVIPs) {
			withdrawVIPs = append(withdrawVIPs, serviceVIP)
		}
	}
	nrc.withdrawVIPs(withdrawVIPs)
}

func (nrc *NetworkRoutingController) tryHandleServiceUpdate(objOld, objNew interface{}) {
	svcOld := getServiceObject(objOld)
	svcNew := getServiceObject(objNew)

	// We expect at least svcNew to be non-nil in order to process this service update, if not get out quick
	if svcNew == nil {
		klog.Warningf("received a nil service objects, aborting as we can't continue")
		return
	}

	klog.V(1).Infof("attempting to update service %s:%s", svcNew.Namespace, svcNew.Name)

	// If the service is headless and the previous version of the service is either non-existent or also headless,
	// skip processing as we only work with VIPs in the next section. Since the ClusterIP field is immutable we
	// don't need to consider previous versions of the service here as we are guaranteed if is a ClusterIP now,
	// it was a ClusterIP before.
	if utils.ServiceIsHeadless(objNew) {
		klog.V(1).Infof("%s/%s is headless, skipping...", svcNew.Namespace, svcNew.Name)
		return
	}

	nrc.handleServiceUpdate(svcOld, svcNew)
}

func (nrc *NetworkRoutingController) tryHandleServiceDelete(oldObj interface{}, logMsgFormat string) {
	oldSvc, ok := oldObj.(*v1core.Service)
	if !ok {
		tombstone, ok := oldObj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("unexpected object type: %v", oldObj)
			return
		}
		if oldSvc, ok = tombstone.Obj.(*v1core.Service); !ok {
			klog.Errorf("unexpected object type: %v", oldObj)
			return
		}
	}
	klog.V(1).Infof(logMsgFormat, oldSvc.Namespace, oldSvc.Name)

	// If the service is headless skip processing as we only work with VIPs in the next section.
	if utils.ServiceIsHeadless(oldObj) {
		klog.V(1).Infof("%s/%s is headless, skipping...", oldSvc.Namespace, oldSvc.Name)
		return
	}

	nrc.handleServiceDelete(oldSvc)
}

// OnServiceCreate handles new service create event from the kubernetes API server
func (nrc *NetworkRoutingController) OnServiceCreate(obj interface{}) {
	nrc.tryHandleServiceUpdate(nil, obj)
}

// OnServiceUpdate handles the service relates updates from the kubernetes API server
func (nrc *NetworkRoutingController) OnServiceUpdate(objOld interface{}, objNew interface{}) {
	nrc.tryHandleServiceUpdate(objOld, objNew)
}

// OnServiceDelete handles the service delete updates from the kubernetes API server
func (nrc *NetworkRoutingController) OnServiceDelete(oldObj interface{}) {
	nrc.tryHandleServiceDelete(oldObj, "Received event to delete service: %s/%s from watch API")
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
			// the service delete event handles route withdrawals
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
		klog.V(3).Info("Skipping OnAdd event to endpoint, controller still performing bootup full-sync")
		return
	}

	nrc.OnEndpointsUpdate(obj)
}

// OnEndpointsUpdate handles the endpoint updates from the kubernetes API server
func (nrc *NetworkRoutingController) OnEndpointsUpdate(obj interface{}) {
	ep, ok := obj.(*v1core.Endpoints)
	if !ok {
		klog.Errorf("cache indexer returned obj that is not type *v1.Endpoints")
		return
	}

	if isEndpointsForLeaderElection(ep) {
		return
	}

	klog.V(1).Infof("Received update to endpoint: %s/%s from watch API", ep.Namespace, ep.Name)
	if !nrc.bgpServerStarted {
		klog.V(3).Infof("Skipping update to endpoint: %s/%s, controller still performing bootup full-sync",
			ep.Namespace, ep.Name)
		return
	}

	svc, exists, err := utils.ServiceForEndpoints(&nrc.svcLister, ep)
	if err != nil {
		klog.Errorf("failed to convert endpoints resource to service: %s", err)
		return
	}

	// ignore updates to Endpoints object with no corresponding Service object
	if !exists {
		return
	}

	nrc.tryHandleServiceUpdate(nil, svc)
}

func (nrc *NetworkRoutingController) getClusterIP(svc *v1core.Service) []string {
	clusterIPList := make([]string, 0)
	if svc.Spec.Type == ClusterIPST || svc.Spec.Type == NodePortST || svc.Spec.Type == LoadBalancerST {

		// skip headless services
		if !utils.ClusterIPIsNoneOrBlank(svc.Spec.ClusterIP) {
			clusterIPList = append(clusterIPList, svc.Spec.ClusterIPs...)
			// check to ensure ClusterIP is contained within ClusterIPs - This should always be the case, but we check
			// just to make extra sure
			clusterIPFound := false
			for _, clusterIP := range clusterIPList {
				if svc.Spec.ClusterIP == clusterIP {
					clusterIPFound = true
					break
				}
			}
			if !clusterIPFound {
				clusterIPList = append(clusterIPList, svc.Spec.ClusterIP)
			}
		}
	}
	return clusterIPList
}

func (nrc *NetworkRoutingController) getExternalIPs(svc *v1core.Service) []string {
	externalIPList := make([]string, 0)
	if svc.Spec.Type == ClusterIPST || svc.Spec.Type == NodePortST || svc.Spec.Type == LoadBalancerST {

		// skip headless services
		if !utils.ClusterIPIsNoneOrBlank(svc.Spec.ClusterIP) {
			externalIPList = append(externalIPList, svc.Spec.ExternalIPs...)
		}
	}
	return externalIPList
}

func (nrc *NetworkRoutingController) getLoadBalancerIPs(svc *v1core.Service) []string {
	loadBalancerIPList := make([]string, 0)
	if svc.Spec.Type == LoadBalancerST {
		// skip headless services
		if !utils.ClusterIPIsNoneOrBlank(svc.Spec.ClusterIP) {
			for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
				if len(lbIngress.IP) > 0 {
					loadBalancerIPList = append(loadBalancerIPList, lbIngress.IP)
				}
			}
		}
	}
	return loadBalancerIPList
}

func (nrc *NetworkRoutingController) getChangedVIPs(oldSvc, newSvc *v1core.Service,
	onlyActiveEndpoints bool) ([]string, []string, error) {
	toWithdrawList := make([]string, 0)
	advertiseService := false

	_, hasLocalAnnotation := newSvc.Annotations[svcLocalAnnotation]
	hasLocalTrafficPolicy := newSvc.Spec.ExternalTrafficPolicy == v1core.ServiceExternalTrafficPolicyTypeLocal
	isLocal := hasLocalAnnotation || hasLocalTrafficPolicy

	if onlyActiveEndpoints && isLocal {
		var err error
		advertiseService, err = nrc.nodeHasEndpointsForService(newSvc)
		if err != nil {
			return nil, nil, err
		}
	}

	newServiceVIPs := nrc.getAllVIPsForService(newSvc)
	// This function allows oldSvc to be nil, if this is the case, we don't have any old VIPs to compare against and
	// possibly withdraw instead treat all VIPs as new and return them as either toAdvertise or toWithdraw depending
	// on service configuration
	if oldSvc == nil {
		if advertiseService {
			return newServiceVIPs, nil, nil
		} else {
			return nil, newServiceVIPs, nil
		}
	}
	oldServiceVIPs := nrc.getAllVIPsForService(oldSvc)

	// If we are instructed to only advertise local services and this service doesn't have endpoints on the node we are
	// currently running on, then attempt to withdraw all the VIPs that the old service had.
	if !advertiseService {
		return nil, oldServiceVIPs, nil
	}

	// At this point we're sure that we should be advertising some VIPs, but we need to figure out which VIPs to
	// advertise and which, if any to withdraw.
	toAdvertiseList := newServiceVIPs
	for _, oldServiceVIP := range oldServiceVIPs {
		if !utils.SliceContainsString(oldServiceVIP, toAdvertiseList) {
			toWithdrawList = append(toWithdrawList, oldServiceVIP)
		}
	}

	// It is possible that this host may have the same IP advertised from multiple services, and we don't want to
	// withdraw it if there is an active service for this VIP on a different service than the one that is changing.
	finalToWithdrawList := make([]string, 0)
	allVIPsOnServer, _, err := nrc.getVIPs(onlyActiveEndpoints)
	if err != nil {
		return nil, nil, err
	}
	for _, withdrawVIP := range toWithdrawList {
		if !utils.SliceContainsString(withdrawVIP, allVIPsOnServer) {
			finalToWithdrawList = append(finalToWithdrawList, withdrawVIP)
		}
	}

	return toAdvertiseList, finalToWithdrawList, nil
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

	// We need to account for the niche case where multiple services may have the same VIP, in this case, one service
	// might be ready while the other service is not. We still want to advertise the VIP as long as there is at least
	// one active endpoint on the node, or we might introduce a service disruption.
	finalToWithdrawList := make([]string, 0)
	for _, withdrawVIP := range toWithdrawList {
		if !utils.SliceContainsString(withdrawVIP, toAdvertiseList) {
			finalToWithdrawList = append(finalToWithdrawList, withdrawVIP)
		}
	}

	return toAdvertiseList, finalToWithdrawList, nil
}

func (nrc *NetworkRoutingController) shouldAdvertiseService(svc *v1core.Service, annotation string,
	defaultValue bool) bool {
	returnValue := defaultValue
	stringValue, exists := svc.Annotations[annotation]
	if exists {
		// Service annotations overrides defaults.
		returnValue, _ = strconv.ParseBool(stringValue)
	}
	return returnValue
}

func (nrc *NetworkRoutingController) getVIPsForService(svc *v1core.Service,
	onlyActiveEndpoints bool) ([]string, []string, error) {

	advertise := true

	_, hasLocalAnnotation := svc.Annotations[svcLocalAnnotation]
	hasLocalTrafficPolicy := svc.Spec.ExternalTrafficPolicy == v1core.ServiceExternalTrafficPolicyTypeLocal
	isLocal := hasLocalAnnotation || hasLocalTrafficPolicy

	if onlyActiveEndpoints && isLocal {
		var err error
		advertise, err = nrc.nodeHasEndpointsForService(svc)
		if err != nil {
			return nil, nil, err
		}
	}

	ipList := nrc.getAllVIPsForService(svc)

	if !advertise {
		return nil, ipList, nil
	}

	return ipList, nil, nil
}

func (nrc *NetworkRoutingController) getAllVIPsForService(svc *v1core.Service) []string {

	ipList := make([]string, 0)

	if nrc.shouldAdvertiseService(svc, svcAdvertiseClusterAnnotation, nrc.advertiseClusterIP) {
		clusterIPs := nrc.getClusterIP(svc)
		if len(clusterIPs) > 0 {
			ipList = append(ipList, clusterIPs...)
		}
	}

	if nrc.shouldAdvertiseService(svc, svcAdvertiseExternalAnnotation, nrc.advertiseExternalIP) {
		ipList = append(ipList, nrc.getExternalIPs(svc)...)
	}

	// Deprecated: Use service.advertise.loadbalancer=false instead of service.skiplbips.
	_, skiplbips := svc.Annotations[svcSkipLbIpsAnnotation]
	advertiseLoadBalancer := nrc.shouldAdvertiseService(svc, svcAdvertiseLoadBalancerAnnotation,
		nrc.advertiseLoadBalancerIP)
	if advertiseLoadBalancer && !skiplbips {
		ipList = append(ipList, nrc.getLoadBalancerIPs(svc)...)
	}

	return ipList

}

func isEndpointsForLeaderElection(ep *v1core.Endpoints) bool {
	_, isLeaderElection := ep.Annotations[resourcelock.LeaderElectionRecordAnnotationKey]
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

	// Find all the IPs that this node has on it so that we can use it to compare it against endpoint IPs
	allNodeIPs := make([]string, 0)
	for _, ips := range maps.Values(nrc.nodeIPv4Addrs) {
		for _, ip := range ips {
			allNodeIPs = append(allNodeIPs, ip.String())
		}
	}
	for _, ips := range maps.Values(nrc.nodeIPv6Addrs) {
		for _, ip := range ips {
			allNodeIPs = append(allNodeIPs, ip.String())
		}
	}

	for _, subset := range ep.Subsets {
		for _, address := range subset.Addresses {
			if address.NodeName != nil {
				if *address.NodeName == nrc.nodeName {
					return true, nil
				}
			} else {
				for _, nodeIP := range allNodeIPs {
					if address.IP == nodeIP {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}
