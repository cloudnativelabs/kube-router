package routing

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/golang/glog"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	v1core "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
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
			nrc.OnServiceUpdate(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nrc.OnServiceUpdate(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			nrc.OnServiceDelete(obj)
		},
	}
}

// OnServiceUpdate handles the service relates updates from the kubernetes API server
func (nrc *NetworkRoutingController) OnServiceUpdate(obj interface{}) {
	svc, ok := obj.(*v1core.Service)
	if !ok {
		glog.Errorf("cache indexer returned obj that is not type *v1.Service")
		return
	}

	glog.V(1).Infof("Received update to service: %s/%s from watch API", svc.Namespace, svc.Name)
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
	err = nrc.addExportPolicies()
	if err != nil {
		glog.Errorf("Error adding BGP export policies: %s", err.Error())
	}

	if len(toAdvertise) > 0 {
		nrc.advertiseVIPs(toAdvertise)
	}

	if len(toWithdraw) > 0 {
		nrc.withdrawVIPs(toWithdraw)
	}
}

// OnServiceDelete handles the service delete updates from the kubernetes API server
func (nrc *NetworkRoutingController) OnServiceDelete(obj interface{}) {
	if !nrc.bgpServerStarted {
		return
	}

	svc, ok := obj.(*v1core.Service)
	if !ok {
		glog.Errorf("cache indexer returned obj that is not type *v1.Service")
		return
	}

	glog.V(1).Infof("Received event to delete service: %s/%s from watch API", svc.Namespace, svc.Name)
	toAdvertise, toWithdraw, err := nrc.getVIPsForService(svc, true)
	if err != nil {
		glog.Errorf("failed to get clean up routes for deleted service: %s/%s", svc.Namespace, svc.Name)
		return
	}

	// update export policies so that deleted VIP's gets removed from clusteripprefixsit
	err = nrc.addExportPolicies()
	if err != nil {
		glog.Errorf("Error adding BGP export policies: %s", err.Error())
	}

	if len(toAdvertise) > 0 {
		nrc.withdrawVIPs(toAdvertise)
	}

	if len(toWithdraw) > 0 {
		nrc.withdrawVIPs(toWithdraw)
	}
}

func (nrc *NetworkRoutingController) newEndpointsEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nrc.OnEndpointsUpdate(obj)
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

	toAdvertise, toWithdraw, err := nrc.getVIPsForService(svc, true)
	if err != nil {
		glog.Errorf("error getting routes for service: %s, err: %s", svc.Name, err)
		return
	}

	if len(toAdvertise) > 0 {
		nrc.advertiseVIPs(toAdvertise)
	}

	if len(toWithdraw) > 0 {
		nrc.withdrawVIPs(toWithdraw)
	}
}

func (nrc *NetworkRoutingController) serviceForEndpoints(ep *v1core.Endpoints) (*v1core.Service, error) {
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

	svc, ok := item.(*v1core.Service)
	if !ok {
		return nil, errors.New("type assertion failed for object in service indexer")
	}

	return svc, nil
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
			_, skiplbips := svc.ObjectMeta.Annotations["kube-router.io/service.skiplbips"]
			if !skiplbips {
				for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
					if len(lbIngress.IP) > 0 {
						loadBalancerIpList = append(loadBalancerIpList, lbIngress.IP)
					}
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

func (nrc *NetworkRoutingController) getVIPsForService(svc *v1core.Service, onlyActiveEndpoints bool) ([]string, []string, error) {
	ipList := make([]string, 0)
	var err error

	nodeHasEndpoints := true
	if onlyActiveEndpoints {
		var maxPaths int = 0
		if len(svc.Annotations[bgpMaxPathsAnnotation]) > 0 {
			maxPaths, err = strconv.Atoi(svc.Annotations[bgpMaxPathsAnnotation])
			if err != nil {
				glog.Errorf("Unable to parse %s on service %s", bgpMaxPathsAnnotation, svc.Name)
				maxPaths = 0
			}
		}
		if maxPaths > 0 {
			pathsStateString := svc.Annotations[bgpMaxPathsStateAnnotation]
			var pathsState []string
			if len(pathsStateString) > 0 {
				err = json.Unmarshal([]byte(pathsStateString), &pathsState)
				if err != nil {
					glog.Errorf("unable to parse service %s annotation %s as json array of strings: %s", svc.Name, bgpMaxPathsStateAnnotation, err)
				}
			}

			var node *v1core.Node
			node, err = utils.GetNodeObject(nrc.clientset, nrc.hostnameOverride)
			if err != nil {
				return nil, nil, err
			}

			nodeHasEndpoints = utils.ArrayHasString(pathsState, node.Name)

			// attempt to allocate our node as a path as there are available
			// paths left and this node isn't among the assigned paths yet
			//
			// if there are more paths than maxPaths, attempt to drop a path
			// off the end
			if (!nodeHasEndpoints && maxPaths > len(pathsState)) || maxPaths < len(pathsState) {
				retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					var result *v1core.Service
					result, err = nrc.clientset.CoreV1().Services(svc.Namespace).Get(svc.Name, v1meta.GetOptions{})
					if err != nil {
						return err
					}
					svc = result

					if len(svc.Annotations[bgpMaxPathsAnnotation]) > 0 {
						maxPaths, err = strconv.Atoi(svc.Annotations[bgpMaxPathsAnnotation])
						if err != nil {
							glog.Errorf("Unable to parse %s on service %s", bgpMaxPathsAnnotation, svc.Name)
							maxPaths = 0
						}
					} else {
						maxPaths = 0
					}

					// if service changed paths to zero while we were trying
					// to claim a path, exit now
					pathsState = []string{}
					if maxPaths == 0 {
						return nil
					}

					pathsStateString = svc.Annotations[bgpMaxPathsStateAnnotation]
					if len(pathsStateString) > 0 {
						err = json.Unmarshal([]byte(pathsStateString), &pathsState)
						if err != nil {
							glog.Errorf("unable to parse service %s annotation %s as json array of strings: %s", svc.Name, bgpMaxPathsAnnotation, err)
						}
					}

					// verify space still available, then update
					nodeHasEndpoints = utils.ArrayHasString(pathsState, node.Name)
					var pathStateBytes []byte
					var modified bool = false
					if !nodeHasEndpoints && maxPaths > len(pathsState) {
						pathsState = append(pathsState, node.Name)

						pathStateBytes, _ = json.Marshal(pathsState)
						svc.Annotations[bgpMaxPathsStateAnnotation] = string(pathStateBytes)
						modified = true
						glog.V(1).Infof("Attempting to add node %s to paths on service %s", node.Name, svc.Name)

					} else if maxPaths < len(pathsState) {
						pathsState = pathsState[:len(pathsState)-1]

						pathStateBytes, _ = json.Marshal(pathsState)
						svc.Annotations[bgpMaxPathsStateAnnotation] = string(pathStateBytes)
						modified = true
						glog.V(1).Infof("Attempting to remove last path on service %s", node.Name, svc.Name)
					}

					if modified {
						result, err = nrc.clientset.CoreV1().Services(svc.Namespace).Update(svc)
						if err != nil {
							return err
						}
						svc = result
					}

					return nil
				})

				if retryErr != nil {
					glog.Errorf("unable to update paths for service %s: %s", svc.Name, retryErr)
				}
			}

			glog.V(1).Infof("Max paths advertise route to service %s: %v", svc.Name, nodeHasEndpoints)
		} else {
			_, isLocal := svc.Annotations[svcLocalAnnotation]
			if isLocal || svc.Spec.ExternalTrafficPolicy == v1core.ServiceExternalTrafficPolicyTypeLocal {
				nodeHasEndpoints, err = nrc.nodeHasEndpointsForService(svc)
				if err != nil {
					return nil, nil, err
				}
			}
		}
	}

	if nrc.advertiseClusterIP {
		clusterIp := nrc.getClusterIp(svc)
		if clusterIp != "" {
			ipList = append(ipList, clusterIp)
		}
	}
	if nrc.advertiseExternalIP {
		ipList = append(ipList, nrc.getExternalIps(svc)...)
	}
	if nrc.advertiseLoadBalancerIP {
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
