package routing

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/utils"

	"strings"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
)

// bgpAdvertiseVIP advertises the service vip (cluster ip or load balancer ip or external IP) the configured peers
func (nrc *NetworkRoutingController) bgpAdvertiseVIP(vip string) error {

	klog.V(2).Infof("Advertising route: '%s/%s via %s' to peers",
		vip, strconv.Itoa(32), nrc.primaryIP.String())

	a1, _ := anypb.New(&gobgpapi.OriginAttribute{
		Origin: 0,
	})
	a2, _ := anypb.New(&gobgpapi.NextHopAttribute{
		NextHop: nrc.primaryIP.String(),
	})
	attrs := []*anypb.Any{a1, a2}
	nlri1, _ := anypb.New(&gobgpapi.IPAddressPrefix{
		Prefix:    vip,
		PrefixLen: 32,
	})
	_, err := nrc.bgpServer.AddPath(context.Background(), &gobgpapi.AddPathRequest{
		Path: &gobgpapi.Path{
			Family: &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_UNICAST},
			Nlri:   nlri1,
			Pattrs: attrs,
		},
	})

	if nrc.MetricsEnabled {
		metrics.ControllerBGPadvertisementsSent.WithLabelValues("advertise-vip").Inc()
	}

	return err
}

// bgpWithdrawVIP  unadvertises the service vip
func (nrc *NetworkRoutingController) bgpWithdrawVIP(vip string) error {
	klog.V(2).Infof("Withdrawing route: '%s/%s via %s' to peers",
		vip, strconv.Itoa(32), nrc.primaryIP.String())

	a1, _ := anypb.New(&gobgpapi.OriginAttribute{
		Origin: 0,
	})
	a2, _ := anypb.New(&gobgpapi.NextHopAttribute{
		NextHop: nrc.primaryIP.String(),
	})
	attrs := []*anypb.Any{a1, a2}
	nlri, _ := anypb.New(&gobgpapi.IPAddressPrefix{
		Prefix:    vip,
		PrefixLen: 32,
	})
	path := gobgpapi.Path{
		Family: &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_UNICAST},
		Nlri:   nlri,
		Pattrs: attrs,
	}
	err := nrc.bgpServer.DeletePath(context.Background(), &gobgpapi.DeletePathRequest{
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
			nrc.OnServiceUpdate(newObj, oldObj)
		},
		DeleteFunc: func(obj interface{}) {
			nrc.OnServiceDelete(obj)
		},
	}
}

func getServiceObject(obj interface{}) (svc *v1core.Service) {
	if svc, _ = obj.(*v1core.Service); svc == nil {
		klog.Errorf("cache indexer returned obj that is not type *v1.Service")
	}
	return
}

func (nrc *NetworkRoutingController) handleServiceUpdate(svc *v1core.Service) {
	if !nrc.bgpServerStarted {
		klog.V(3).Infof("Skipping update to service: %s/%s, controller still performing bootup full-sync",
			svc.Namespace, svc.Name)
		return
	}

	toAdvertise, toWithdraw, err := nrc.getActiveVIPs()
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

func (nrc *NetworkRoutingController) handleServiceDelete(svc *v1core.Service) {

	if !nrc.bgpServerStarted {
		klog.V(3).Infof("Skipping update to service: %s/%s, controller still performing bootup full-sync",
			svc.Namespace, svc.Name)
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
	activeVIPsMap := make(map[string]bool)
	for _, activeVIP := range activeVIPs {
		activeVIPsMap[activeVIP] = true
	}
	advertiseIPList, unadvertiseIPList := nrc.getAllVIPsForService(svc)
	//nolint:gocritic // we understand that we're assigning to a new slice
	allIPList := append(advertiseIPList, unadvertiseIPList...)
	withdrawVIPs := make([]string, 0)
	for _, serviceVIP := range allIPList {
		// withdraw VIP only if deleted service is the last service using the VIP
		if !activeVIPsMap[serviceVIP] {
			withdrawVIPs = append(withdrawVIPs, serviceVIP)
		}
	}
	nrc.withdrawVIPs(withdrawVIPs)

}

func (nrc *NetworkRoutingController) tryHandleServiceUpdate(obj interface{}, logMsgFormat string) {
	if svc := getServiceObject(obj); svc != nil {
		klog.V(1).Infof(logMsgFormat, svc.Namespace, svc.Name)

		// If the service is headless and the previous version of the service is either non-existent or also headless,
		// skip processing as we only work with VIPs in the next section. Since the ClusterIP field is immutable we
		// don't need to consider previous versions of the service here as we are guaranteed if is a ClusterIP now,
		// it was a ClusterIP before.
		if utils.ServiceIsHeadless(obj) {
			klog.V(1).Infof("%s/%s is headless, skipping...", svc.Namespace, svc.Name)
			return
		}

		nrc.handleServiceUpdate(svc)
	}
}

func (nrc *NetworkRoutingController) tryHandleServiceDelete(obj interface{}, logMsgFormat string) {
	svc, ok := obj.(*v1core.Service)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
		if svc, ok = tombstone.Obj.(*v1core.Service); !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
	}
	klog.V(1).Infof(logMsgFormat, svc.Namespace, svc.Name)

	// If the service is headless skip processing as we only work with VIPs in the next section.
	if utils.ServiceIsHeadless(obj) {
		klog.V(1).Infof("%s/%s is headless, skipping...", svc.Namespace, svc.Name)
		return
	}

	nrc.handleServiceDelete(svc)
}

// OnServiceCreate handles new service create event from the kubernetes API server
func (nrc *NetworkRoutingController) OnServiceCreate(obj interface{}) {
	nrc.tryHandleServiceUpdate(obj, "Received new service: %s/%s from watch API")
}

// OnServiceUpdate handles the service relates updates from the kubernetes API server
func (nrc *NetworkRoutingController) OnServiceUpdate(objNew interface{}, objOld interface{}) {
	nrc.tryHandleServiceUpdate(objNew, "Received update on service: %s/%s from watch API")

	// This extra call needs to be here, because during the update the list of externalIPs may have changed and
	// externalIPs is the only service VIP field that is:
	// a) mutable after first creation
	// b) an array
	//
	// This means that while we only need to withdraw ClusterIP VIPs and LoadBalancer VIPs on delete, we may need
	// to withdraw ExternalIPs on update.
	//
	// As such, it needs to be handled differently as nrc.handleServiceUpdate only withdraws VIPs if the service
	// endpoint is no longer scheduled on this node and its a local type service.
	nrc.withdrawVIPs(nrc.getExternalIPsToWithdraw(getServiceObject(objOld), getServiceObject(objNew)))
}

func (nrc *NetworkRoutingController) getExternalIPsToWithdraw(svcOld, svcNew *v1core.Service) (out []string) {
	withdrawnServiceVips := make([]string, 0)
	if svcOld != nil && svcNew != nil {
		withdrawnServiceVips = getMissingPrevGen(nrc.getExternalIPs(svcOld), nrc.getExternalIPs(svcNew))
	}
	// ensure external IP to be withdrawn is not used by any other service
	allActiveVIPs, _, err := nrc.getActiveVIPs()
	if err != nil {
		klog.Errorf("failed to get all active VIP's due to: %s", err.Error())
		return
	}
	activeVIPsMap := make(map[string]bool)
	for _, activeVIP := range allActiveVIPs {
		activeVIPsMap[activeVIP] = true
	}
	for _, serviceVIP := range withdrawnServiceVips {
		// withdraw VIP only if updated service is the last service using the VIP
		if !activeVIPsMap[serviceVIP] {
			out = append(out, serviceVIP)
		}
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
	nrc.tryHandleServiceDelete(obj, "Received event to delete service: %s/%s from watch API")
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

	nrc.tryHandleServiceUpdate(svc, "Updating service %s/%s triggered by endpoint update event")
}

func (nrc *NetworkRoutingController) getClusterIP(svc *v1core.Service) string {
	clusterIP := ""
	if svc.Spec.Type == ClusterIPST || svc.Spec.Type == NodePortST || svc.Spec.Type == LoadBalancerST {

		// skip headless services
		if !utils.ClusterIPIsNoneOrBlank(svc.Spec.ClusterIP) {
			clusterIP = svc.Spec.ClusterIP
		}
	}
	return clusterIP
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
	// one active endpoint on the node or we might introduce a service disruption.
	finalToWithdrawList := make([]string, 0)
OUTER:
	for _, withdrawVIP := range toWithdrawList {
		for _, advertiseVIP := range toAdvertiseList {
			if withdrawVIP == advertiseVIP {
				// if there is a VIP that is set to both be advertised and withdrawn, don't add it to the final
				// withdraw list
				continue OUTER
			}
		}
		finalToWithdrawList = append(finalToWithdrawList, withdrawVIP)
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

	advertiseIPList, unAdvertisedIPList := nrc.getAllVIPsForService(svc)

	if !advertise {
		//nolint:gocritic // we understand that we're assigning to a new slice
		allIPList := append(advertiseIPList, unAdvertisedIPList...)
		return nil, allIPList, nil
	}

	return advertiseIPList, unAdvertisedIPList, nil
}

func (nrc *NetworkRoutingController) getAllVIPsForService(svc *v1core.Service) ([]string, []string) {

	advertisedIPList := make([]string, 0)
	unAdvertisedIPList := make([]string, 0)

	clusterIP := nrc.getClusterIP(svc)
	if clusterIP != "" {
		if nrc.shouldAdvertiseService(svc, svcAdvertiseClusterAnnotation, nrc.advertiseClusterIP) {
			advertisedIPList = append(advertisedIPList, clusterIP)
		} else {
			unAdvertisedIPList = append(unAdvertisedIPList, clusterIP)
		}
	}

	externalIPs := nrc.getExternalIPs(svc)
	if len(externalIPs) > 0 {
		if nrc.shouldAdvertiseService(svc, svcAdvertiseExternalAnnotation, nrc.advertiseExternalIP) {
			advertisedIPList = append(advertisedIPList, externalIPs...)
		} else {
			unAdvertisedIPList = append(unAdvertisedIPList, externalIPs...)
		}
	}

	// Deprecated: Use service.advertise.loadbalancer=false instead of service.skiplbips.
	lbIPs := nrc.getLoadBalancerIPs(svc)
	if len(lbIPs) > 0 {
		_, skiplbips := svc.Annotations[svcSkipLbIpsAnnotation]
		advertiseLoadBalancer := nrc.shouldAdvertiseService(svc, svcAdvertiseLoadBalancerAnnotation,
			nrc.advertiseLoadBalancerIP)
		if advertiseLoadBalancer && !skiplbips {
			advertisedIPList = append(advertisedIPList, lbIPs...)
		} else {
			unAdvertisedIPList = append(unAdvertisedIPList, lbIPs...)
		}
	}

	return advertisedIPList, unAdvertisedIPList

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

	for _, subset := range ep.Subsets {
		for _, address := range subset.Addresses {
			if address.NodeName != nil {
				if *address.NodeName == nrc.nodeName {
					return true, nil
				}
			} else {
				if address.IP == nrc.primaryIP.String() {
					return true, nil
				}
			}
		}
	}

	return false, nil
}
