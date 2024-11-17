package lballoc

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

const loadBalancerClassName = "kube-router"

type ipRanges struct {
	ipRanges   []net.IPNet
	rangeIndex int
	currentIP  net.IP
}

type LoadBalancerController struct {
	ipv4Ranges   *ipRanges
	ipv6Ranges   *ipRanges
	svcLister    cache.Indexer
	lock         *resourcelock.LeaseLock
	addChan      chan v1core.Service
	allocateChan chan v1core.Service
	clientset    kubernetes.Interface
	isDefault    bool
	syncPeriod   time.Duration
	unitTestWG   *sync.WaitGroup
}

func getNamespace() (namespace string, err error) {
	ns := os.Getenv("POD_NAMESPACE")
	if ns != "" {
		return ns, nil
	}

	nb, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err == nil {
		return string(nb), nil
	}

	return "", errors.New("unable to get namespace from kubernetes environment or $POD_NAMESPACE")
}

func getPodname() (podname string, err error) {
	podname = os.Getenv("POD_NAME")
	if podname != "" {
		return podname, nil
	}
	return "", errors.New("unable to get pod name from $POD_NAME")
}

func copyIP(ip net.IP) net.IP {
	return append(net.IP{}, ip...)
}

func newipRanges(ranges []net.IPNet) *ipRanges {
	var cip net.IP
	if len(ranges) == 0 {
		cip = nil
	} else {
		cip = copyIP(ranges[0].IP)
	}
	ir := &ipRanges{
		ipRanges:  ranges,
		currentIP: cip,
	}

	return ir
}

func (ir *ipRanges) inc() {
	cn := ir.ipRanges[ir.rangeIndex]
	ci := copyIP(ir.currentIP)

	// Increment the current IP address
	// 10.0.0.3 will increment to 10.0.0.4
	// 10.0.0.255 will increment to 10.0.1.0
	for i := len(ci) - 1; i >= 0; i-- {
		ci[i]++
		if ci[i] > 0 { // if the byte didn't overflow to zero, don't increment the byte to the left
			break
		}
	}

	// If the new address is not in the current IP range, move to the first IP in the next range
	// If the current range is the last, move to the first IP in the first range
	if !cn.Contains(ci) {
		if ir.rangeIndex == len(ir.ipRanges)-1 {
			ir.rangeIndex = 0
		} else {
			ir.rangeIndex++
		}
		ci = copyIP(ir.ipRanges[ir.rangeIndex].IP)
	}

	ir.currentIP = ci
}

func ipInAllocated(ip net.IP, allocated []net.IP) bool {
	for _, cip := range allocated {
		if cip.Equal(ip) {
			return true
		}
	}
	return false
}

func (ir *ipRanges) getNextFreeIP(allocated []net.IP) (net.IP, error) {
	startIP := copyIP(ir.currentIP)
	if len(startIP) == 0 {
		return nil, errors.New("no IPs left to allocate")
	}
	ip := startIP
	for {
		if !ipInAllocated(ip, allocated) {
			return ip, nil
		}
		ir.inc()
		ip = ir.currentIP
		if ip.Equal(startIP) {
			break
		}
	}
	return nil, errors.New("no IPs left to allocate")
}

func (ir *ipRanges) Len() int {
	return len(ir.ipRanges)
}

func (ir *ipRanges) Contains(ip net.IP) bool {
	for _, in := range ir.ipRanges {
		if in.Contains(ip) {
			return true
		}
	}
	return false
}

func (lbc *LoadBalancerController) runLeaderElection(ctx context.Context, isLeaderChan chan<- bool) {
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lbc.lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second, //nolint:gomnd // No reason for a 15 second constant
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(c context.Context) {
				isLeaderChan <- true
			},
			OnStoppedLeading: func() {
				isLeaderChan <- false
			},
			OnNewLeader: func(_ string) {},
		},
	})
}

func (lbc *LoadBalancerController) OnAdd(obj interface{}, isInitialList bool) {
	if svc, ok := obj.(*v1core.Service); ok {
		lbc.addChan <- *svc
	}
}

func (lbc *LoadBalancerController) OnDelete(obj interface{}) {
}

func (lbc *LoadBalancerController) OnUpdate(oldObj interface{}, newObj interface{}) {
	if svc, ok := newObj.(*v1core.Service); ok {
		lbc.addChan <- *svc
	}
}

func getIPFamilies(families []v1core.IPFamily) (v4, v6 bool) {
	for _, ipf := range families {
		//nolint:exhaustive // we don't need exhaustive searching for IP Families
		switch ipf {
		case v1core.IPv4Protocol:
			v4 = true
		case v1core.IPv6Protocol:
			v6 = true
		}
	}
	return v4, v6
}

func getCurrentIngressFamilies(svc *v1core.Service) (v4, v6 bool) {
	for _, lbi := range svc.Status.LoadBalancer.Ingress {
		ip := net.ParseIP(lbi.IP)
		switch {
		case ip == nil:
			continue
		case ip.To4() != nil:
			v4 = true
		case ip.To4() == nil:
			v6 = true
		}
	}
	return v4, v6
}

func checkIngress(svc *v1core.Service) bool {
	want4, want6 := getIPFamilies(svc.Spec.IPFamilies)
	have4, have6 := getCurrentIngressFamilies(svc)

	if want4 != have4 {
		return true
	}
	if want6 != have6 {
		return true
	}
	return false
}

func (lbc *LoadBalancerController) checkClass(svc *v1core.Service) bool {
	cls := ""
	if svc.Spec.LoadBalancerClass != nil {
		cls = *svc.Spec.LoadBalancerClass
	}

	switch {
	case cls == loadBalancerClassName:
		return true
	case lbc.isDefault && cls == "default":
		return true
	case lbc.isDefault && cls == "":
		return true
	}

	return false
}

func (lbc *LoadBalancerController) shouldAllocate(svc *v1core.Service) bool {
	if svc.Spec.Type != v1core.ServiceTypeLoadBalancer {
		return false
	}
	if !lbc.checkClass(svc) {
		return false
	}
	if !checkIngress(svc) {
		return false
	}

	return true
}

func (lbc *LoadBalancerController) walkServices() {
	var svc *v1core.Service
	var ok bool
	for _, obj := range lbc.svcLister.List() {
		if svc, ok = obj.(*v1core.Service); !ok {
			continue
		}
		if lbc.shouldAllocate(svc) {
			lbc.addChan <- *svc
		}
	}
}

func (lbc *LoadBalancerController) canAllocate(svc v1core.Service) error {
	canV4 := lbc.ipv4Ranges.Len() != 0
	canV6 := lbc.ipv6Ranges.Len() != 0
	requireDual := (svc.Spec.IPFamilyPolicy != nil && *svc.Spec.IPFamilyPolicy == v1core.IPFamilyPolicyRequireDualStack)
	if requireDual && !canV4 {
		return errors.New("IPv4 address required, but no IPv4 ranges available")
	}
	if requireDual && !canV6 {
		return errors.New("IPv6 address required, but no IPv6 ranges available")
	}

	ipv4, ipv6 := getIPFamilies(svc.Spec.IPFamilies)
	if ipv4 && !canV4 && !ipv6 {
		return errors.New("no IPv4 ranges specified")
	}
	if ipv6 && !canV6 && !ipv4 {
		return errors.New("no IPv6 ranges specified")
	}

	return nil
}

func (lbc *LoadBalancerController) getIPsFromService(svc *v1core.Service) ([]net.IP, []net.IP) {
	v4 := make([]net.IP, 0)
	v6 := make([]net.IP, 0)

	allips := make([]string, 0)
	allips = append(allips, svc.Spec.ExternalIPs...)
	for _, lin := range svc.Status.LoadBalancer.Ingress {
		if lin.IP == "" {
			continue
		}
		allips = append(allips, lin.IP)
	}

	for _, sip := range allips {
		ip := net.ParseIP(sip)
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		switch {
		case ip4 != nil && lbc.ipv4Ranges.Contains(ip4):
			v4 = append(v4, ip4)
		case lbc.ipv6Ranges.Contains(ip):
			v6 = append(v6, ip)
		}
	}

	return v4, v6
}

func (lbc *LoadBalancerController) getAllocatedIPs() ([]net.IP, []net.IP) {
	allocated4 := make([]net.IP, 0)
	allocated6 := make([]net.IP, 0)
	var svc *v1core.Service
	var ok bool
	for _, obj := range lbc.svcLister.List() {
		if svc, ok = obj.(*v1core.Service); !ok {
			continue
		}
		ips4, ips6 := lbc.getIPsFromService(svc)
		allocated4 = append(allocated4, ips4...)
		allocated6 = append(allocated6, ips6...)
	}
	return allocated4, allocated6
}

func appendIngressIP(svc *v1core.Service, ip net.IP) {
	lbi := v1core.LoadBalancerIngress{
		IP: ip.String(),
	}
	svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, lbi)
}

func (lbc *LoadBalancerController) updateService(svc *v1core.Service, ips ...net.IP) {
	// This is only non-nil during certain unit tests that need to understand when this goroutine is finished to remove
	// chance of race conditions
	if lbc.unitTestWG != nil {
		defer lbc.unitTestWG.Done()
	}

	if lbc.clientset == nil {
		panic("clientset")
	}
	if lbc.clientset.CoreV1() == nil {
		panic("corev1")
	}
	svcClient := lbc.clientset.CoreV1().Services(svc.Namespace)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		curSvc, err := svcClient.Get(context.TODO(), svc.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			appendIngressIP(curSvc, ip)
		}
		_, err = svcClient.UpdateStatus(context.TODO(), curSvc, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		klog.Errorf("unable to update %s in %s: %s", svc.Name, svc.Namespace, err)
	}
}

func (lbc *LoadBalancerController) allocateService(svc *v1core.Service) error {
	allocated4, allocated6 := lbc.getAllocatedIPs()

	requireDual := (svc.Spec.IPFamilyPolicy != nil && *svc.Spec.IPFamilyPolicy == v1core.IPFamilyPolicyRequireDualStack)
	want4, want6 := getIPFamilies(svc.Spec.IPFamilies)
	have4, have6 := getCurrentIngressFamilies(svc)

	var ipv4, ipv6 net.IP
	var err4, err6 error
	if want4 && !have4 {
		ipv4, err4 = lbc.ipv4Ranges.getNextFreeIP(allocated4)
	}
	if want6 && !have6 {
		ipv6, err6 = lbc.ipv6Ranges.getNextFreeIP(allocated6)
	}
	err := err6
	if err4 != nil {
		err = err4
	}

	if ipv4 == nil && ipv6 == nil {
		return errors.New("unable to allocate address: " + err.Error())
	}
	if (ipv4 == nil || ipv6 == nil) && requireDual {
		return errors.New("unable to allocate dual-stack addresses: " + err.Error())
	}

	// This is only non-nil during certain unit tests that need to understand when this goroutine is finished to remove
	// chance of race conditions
	if lbc.unitTestWG != nil {
		lbc.unitTestWG.Add(1)
	}
	go lbc.updateService(svc, ipv4, ipv6)
	return nil
}

func (lbc *LoadBalancerController) allocator() {
	for svc := range lbc.allocateChan {
		err := lbc.canAllocate(svc)
		if err != nil {
			klog.Errorf("can not allocate address for %s in %s: %s",
				svc.Name, svc.Namespace, err)
			continue
		}
		err = lbc.allocateService(&svc)
		if err != nil {
			klog.Errorf("failed to allocate address for %s in %s: %s",
				svc.Name, svc.Namespace, err)
			continue
		}
	}
}

func (lbc *LoadBalancerController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat,
	stopCh <-chan struct{}, wg *sync.WaitGroup) {
	isLeader := false
	isLeaderChan := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.NewTimer(lbc.syncPeriod)
	defer wg.Done()
	defer cancel()
	defer close(lbc.allocateChan)

	go lbc.runLeaderElection(ctx, isLeaderChan)
	go lbc.allocator()

	for {
		select {
		case <-stopCh:
			klog.Info("shutting down load balancer allocator controller")
			return
		case isLeader = <-isLeaderChan:
			if isLeader {
				klog.Info("became the load balancer controller leader, syncing...")
				go lbc.walkServices()
			}
		case svc := <-lbc.addChan:
			if isLeader && lbc.shouldAllocate(&svc) {
				lbc.allocateChan <- svc
			}
		case <-timer.C:
			timer.Reset(time.Minute)
			healthcheck.SendHeartBeat(healthChan, healthcheck.LoadBalancerController)
			if isLeader {
				go lbc.walkServices()
			}
		}
	}
}

func NewLoadBalancerController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, svcInformer cache.SharedIndexInformer,
) (*LoadBalancerController, error) {
	ranges4 := make([]net.IPNet, 0)
	ranges6 := make([]net.IPNet, 0)

	for _, ir := range config.LoadBalancerCIDRs {
		ip, cidr, err := net.ParseCIDR(ir)
		if err != nil {
			return nil, err
		}
		if ip.To4() != nil && !config.EnableIPv4 {
			return nil, errors.New("IPv4 loadbalancer CIDR specified while IPv4 is disabled")
		}
		if ip.To4() == nil && !config.EnableIPv6 {
			return nil, errors.New("IPv6 loadbalancer CIDR specified while IPv6 is disabled")
		}
		if ip.To4() != nil {
			ranges4 = append(ranges4, *cidr)
		} else {
			ranges6 = append(ranges6, *cidr)
		}
	}

	lbc := &LoadBalancerController{
		ipv4Ranges:   newipRanges(ranges4),
		ipv6Ranges:   newipRanges(ranges6),
		addChan:      make(chan v1core.Service),
		allocateChan: make(chan v1core.Service),
		clientset:    clientset,
		isDefault:    config.LoadBalancerDefaultClass,
		syncPeriod:   config.LoadBalancerSyncPeriod,
	}

	lbc.svcLister = svcInformer.GetIndexer()

	namespace, err := getNamespace()
	if err != nil {
		return nil, err
	}

	podname, err := getPodname()
	if err != nil {
		return nil, err
	}

	lbc.lock = &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      "kube-router-lballoc",
			Namespace: namespace,
		},
		Client: clientset.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: podname,
		},
	}

	return lbc, nil
}
