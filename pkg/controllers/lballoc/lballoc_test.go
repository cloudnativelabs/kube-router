package lballoc

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

const (
	testName         = "falafel"
	testDefaultClass = "default"
)

func TestGetNamespace(t *testing.T) {
	errExp := error(nil)
	t.Setenv("POD_NAMESPACE", testName)
	ns, err := getNamespace()
	if ns != testName {
		t.Fatalf("expected %s, got %s", testName, ns)
	}
	if err != errExp {
		t.Fatalf("expected %s, got %s", errExp, err)
	}
}

func TestGetNamespaceFail(t *testing.T) {
	nsExp := ""
	errExp := errors.New("unable to get namespace from kubernetes environment or $POD_NAMESPACE")
	ns, err := getNamespace()
	if ns != nsExp {
		t.Fatalf("expected \"%s\", got %s", nsExp, ns)
	}
	if err.Error() != errExp.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}
}

func TestGetPodName(t *testing.T) {
	errExp := error(nil)
	t.Setenv("POD_NAME", testName)
	name, err := getPodname()
	if name != testName {
		t.Fatalf("expected %s, got %s", testName, name)
	}
	if err != errExp {
		t.Fatalf("expected %s, got %s", errExp, err)
	}
}

func TestGetPodNameFail(t *testing.T) {
	nameExp := ""
	errExp := errors.New("unable to get pod name from $POD_NAME")
	name, err := getPodname()
	if name != nameExp {
		t.Fatalf("expected \"%s\", got %s", nameExp, name)
	}
	if err.Error() != errExp.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}
}

func TestIPRangesEmpty(t *testing.T) {
	lenExp := 0
	ipExp := net.IP(nil)
	errExp := errors.New("no IPs left to allocate")
	allocated := make([]net.IP, 0)
	ir := newipRanges(nil)

	l := ir.Len()
	if l != lenExp {
		t.Fatalf("expected %d, got %d", lenExp, l)
	}

	ip, err := ir.getNextFreeIP(allocated)
	if ip != nil {
		t.Fatalf("expected %s, got %s", ipExp, ip)
	}
	if err.Error() != errExp.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}
}

func TestIPRange(t *testing.T) {
	lenExp := 1
	ipExp := net.ParseIP("ffff::")
	onesExp := 128
	bitsExp := 128
	errExp := errors.New("no IPs left to allocate")
	containsExp := true
	allocated := make([]net.IP, 0)

	_, ipnet, err := net.ParseCIDR("ffff::/128")
	if err != nil {
		t.Fatalf("expected %s, got %s", error(nil), err)
	}
	ipnets := append([]net.IPNet(nil), *ipnet)
	ir := newipRanges(ipnets)

	l := ir.Len()
	if l != lenExp {
		t.Fatalf("expected %d, got %d", lenExp, l)
	}

	if !ir.ipRanges[0].IP.Equal(ipExp) {
		t.Fatalf("expected %s, got %s", ipExp, ir.ipRanges[0].IP)
	}
	ones, bits := ir.ipRanges[0].Mask.Size()
	if ones != onesExp {
		t.Fatalf("expected %d, got %d", onesExp, ones)
	}
	if bits != bitsExp {
		t.Fatalf("expected %d, got %d", bitsExp, bits)
	}

	ip, err := ir.getNextFreeIP(allocated)
	if !ip.Equal(ipExp) {
		t.Fatalf("expected %s, got %s", ipExp, ip)
	}
	if err != nil {
		t.Fatalf("expected %s, got %s", error(nil), err)
	}

	allocated = append(allocated, ip)

	ip, err = ir.getNextFreeIP(allocated)
	if ip != nil {
		t.Fatalf("expected %s, got %s", net.IP(nil), ip)
	}
	if err.Error() != errExp.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}

	contains := ir.Contains(ipExp)
	if contains != containsExp {
		t.Fatalf("expected %t, got %t", containsExp, contains)
	}
}

func TestGetIPFamilies(t *testing.T) {
	v4Exp := true
	v6Exp := true

	families := append([]v1core.IPFamily{}, v1core.IPv4Protocol, v1core.IPv6Protocol)

	v4, v6 := getIPFamilies(families)

	if v4 != v4Exp {
		t.Fatalf("expected %t, got %t", v4Exp, v4)
	}

	if v6 != v6Exp {
		t.Fatalf("expected %t, got %t", v6Exp, v6)
	}

}

func makeTestService() v1core.Service {
	svc := v1core.Service{
		Spec: v1core.ServiceSpec{
			Type: v1core.ServiceTypeLoadBalancer,
		},
	}
	svc.Name = testName
	svc.Namespace = "tahini"
	svc.Spec.LoadBalancerClass = nil
	svc.Spec.IPFamilies = append([]v1core.IPFamily{}, v1core.IPv4Protocol, v1core.IPv6Protocol)

	return svc
}

func TestGetCurrentIngressFamilies(t *testing.T) {
	svc := makeTestService()
	for _, tip := range []string{"ffff::", "127.127.127.127"} {
		ing := v1core.LoadBalancerIngress{
			IP: tip,
		}
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, ing)
	}

	expV4 := true
	expV6 := true
	v4, v6 := getCurrentIngressFamilies(&svc)
	if expV4 != v4 {
		t.Fatalf("expected %t, got %t", expV4, v4)
	}
	if expV6 != v6 {
		t.Fatalf("expected %t, got %t", expV6, v6)
	}

}

func TestCheckIngress(t *testing.T) {
	svc := makeTestService()

	check := checkIngress(&svc)
	if !check {
		t.Fatalf("expected %t, got %t", true, check)
	}

	v6Ingress := v1core.LoadBalancerIngress{
		IP: "ffff::",
	}
	svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, v6Ingress)

	check = checkIngress(&svc)
	if !check {
		t.Fatalf("expected %t, got %t", true, check)
	}

	v4Ingress := v1core.LoadBalancerIngress{
		IP: "127.127.127.127",
	}
	svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, v4Ingress)

	check = checkIngress(&svc)
	if check {
		t.Fatalf("expected %t, got %t", false, check)
	}
}

func TestCheckClass(t *testing.T) {
	lbc := &LoadBalancerController{
		isDefault: true,
	}

	svc := makeTestService()
	svc.Spec.LoadBalancerClass = nil

	check := lbc.checkClass(&svc)
	if !check {
		t.Fatalf("expected %t, got %t", true, check)
	}

	lbc.isDefault = false
	check = lbc.checkClass(&svc)
	if check {
		t.Fatalf("expected %t, got %t", false, check)
	}

	cls := ""
	svc.Spec.LoadBalancerClass = &cls
	check = lbc.checkClass(&svc)
	if check {
		t.Fatalf("expected %t, got %t", false, check)
	}

	cls = testDefaultClass
	svc.Spec.LoadBalancerClass = &cls
	check = lbc.checkClass(&svc)
	if check {
		t.Fatalf("expected %t, got %t", false, check)
	}

	cls = loadBalancerClassName
	svc.Spec.LoadBalancerClass = &cls
	check = lbc.checkClass(&svc)
	if !check {
		t.Fatalf("expected %t, got %t", true, check)
	}

	lbc.isDefault = true

	cls = ""
	svc.Spec.LoadBalancerClass = &cls
	check = lbc.checkClass(&svc)
	if !check {
		t.Fatalf("expected %t, got %t", true, check)
	}

	cls = testDefaultClass
	svc.Spec.LoadBalancerClass = &cls
	check = lbc.checkClass(&svc)
	if !check {
		t.Fatalf("expected %t, got %t", true, check)
	}

	cls = loadBalancerClassName
	svc.Spec.LoadBalancerClass = &cls
	check = lbc.checkClass(&svc)
	if !check {
		t.Fatalf("expected %t, got %t", true, check)
	}

	cls = testName
	svc.Spec.LoadBalancerClass = &cls
	check = lbc.checkClass(&svc)
	if check {
		t.Fatalf("expected %t, got %t", false, check)
	}

}

func TestShouldAllocate(t *testing.T) {
	lbc := &LoadBalancerController{
		isDefault: true,
	}

	svc := makeTestService()

	check := lbc.shouldAllocate(&svc)
	if !check {
		t.Fatalf("expected %t, got %t", true, check)
	}

	svc.Spec.Type = v1core.ServiceTypeExternalName
	check = lbc.shouldAllocate(&svc)
	if check {
		t.Fatalf("expected %t, got %t", false, check)
	}
	svc.Spec.Type = v1core.ServiceTypeLoadBalancer

	cls := testName
	svc.Spec.LoadBalancerClass = &cls
	check = lbc.shouldAllocate(&svc)
	if check {
		t.Fatalf("expected %t, got %t", false, check)
	}
	svc.Spec.LoadBalancerClass = nil

	svc.Spec.IPFamilies = append([]v1core.IPFamily{}, v1core.IPv4Protocol)
	ingress := v1core.LoadBalancerIngress{
		IP: "127.127.127.127",
	}
	svc.Status.LoadBalancer.Ingress = append([]v1core.LoadBalancerIngress{}, ingress)
	check = lbc.shouldAllocate(&svc)
	if check {
		t.Fatalf("expected %t, got %t", false, check)
	}

	ingress = v1core.LoadBalancerIngress{
		IP: "ffff::",
	}
	svc.Status.LoadBalancer.Ingress = append([]v1core.LoadBalancerIngress{}, ingress)
	check = lbc.shouldAllocate(&svc)
	if !check {
		t.Fatalf("expected %t, got %t", true, check)
	}

}

type mockIndexer struct {
	cache.FakeCustomStore
	objects []interface{}
}

func (mi *mockIndexer) Index(_ string, _ interface{}) ([]interface{}, error) {
	return nil, errors.New("unsupported")
}

func (mi *mockIndexer) IndexKeys(_, _ string) ([]string, error) {
	return nil, errors.New("unsupported")
}

func (mi *mockIndexer) ListIndexFuncValues(_ string) []string {
	return nil
}

func (mi *mockIndexer) ByIndex(_, _ string) ([]interface{}, error) {
	return nil, errors.New("unsupported")
}

func (mi *mockIndexer) GetIndexers() cache.Indexers {
	return nil
}

func (mi *mockIndexer) AddIndexers(_ cache.Indexers) error {
	return errors.New("unsupported")
}

func (mi *mockIndexer) List() []interface{} {
	return mi.objects
}

func newMockIndexer(objects ...interface{}) *mockIndexer {
	mi := &mockIndexer{
		objects: make([]interface{}, 0),
	}
	mi.objects = append(mi.objects, objects...)
	return mi
}

func TestWalkServices(t *testing.T) {
	svc1 := makeTestService()
	svc2 := true
	mi := newMockIndexer(svc1, svc2)
	addChan := make(chan v1core.Service, 2)
	lbc := &LoadBalancerController{
		svcLister: mi,
		addChan:   addChan,
	}

	lbc.walkServices()
	close(lbc.addChan)

	out := make([]v1core.Service, 1)
	for svc := range lbc.addChan {
		out = append(out, svc)
	}

	l := 1
	lenExp := 1
	if len(out) != lenExp {
		t.Fatalf("expected %d, got %d", lenExp, l)
	}
}

func makeIPRanges(ips ...string) (ir4, ir6 *ipRanges) {
	var v4, v6 []net.IPNet
	for _, sip := range ips {
		_, ipn, _ := net.ParseCIDR(sip)
		if ipn == nil {
			continue
		}
		if ipn.IP.To4() != nil {
			v4 = append(v4, *ipn)
		} else {
			v6 = append(v6, *ipn)
		}
	}
	ir4 = newipRanges(v4)
	ir6 = newipRanges(v6)
	return ir4, ir6
}

func TestCanAllocate(t *testing.T) {
	ir4, ir6 := makeIPRanges("127.127.127.127/32", "ffff::/32")
	lbc := &LoadBalancerController{
		ipv4Ranges: ir4,
		ipv6Ranges: ir6,
	}
	ippol := v1core.IPFamilyPolicy("RequireDualStack")
	svc := makeTestService()
	svc.Spec.IPFamilyPolicy = &ippol

	err := lbc.canAllocate(svc)
	if err != nil {
		t.Fatalf("expected %v, got %s", nil, err)
	}

	lbc.ipv4Ranges = newipRanges(nil)
	errExp := errors.New("IPv4 address required, but no IPv4 ranges available")
	err = lbc.canAllocate(svc)
	if err.Error() != errExp.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}

	lbc.ipv4Ranges = ir4
	lbc.ipv6Ranges = newipRanges(nil)
	errExp = errors.New("IPv6 address required, but no IPv6 ranges available")
	err = lbc.canAllocate(svc)
	if err.Error() != errExp.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}

	ippol = v1core.IPFamilyPolicy("PreferDualStack")
	svc.Spec.IPFamilyPolicy = &ippol
	svc.Spec.IPFamilies = append([]v1core.IPFamily{}, v1core.IPv4Protocol)
	err = lbc.canAllocate(svc)
	if err != nil {
		t.Fatalf("expected %v, got %s", nil, err)
	}

	svc.Spec.IPFamilies = append([]v1core.IPFamily{}, v1core.IPv6Protocol)
	err = lbc.canAllocate(svc)
	errExp = errors.New("no IPv6 ranges specified")
	if err.Error() != errExp.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}

	lbc.ipv4Ranges = newipRanges(nil)
	lbc.ipv6Ranges = ir6
	svc.Spec.IPFamilies = append([]v1core.IPFamily{}, v1core.IPv4Protocol)
	err = lbc.canAllocate(svc)
	errExp = errors.New("no IPv4 ranges specified")
	if err.Error() != errExp.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}

	lbc.ipv6Ranges = newipRanges(nil)
	err = lbc.canAllocate(svc)
	errExp = errors.New("no IPv4 ranges specified")
	if err.Error() != errExp.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}
}

func TestGetIPsFromService(t *testing.T) {
	svc := makeTestService()
	ir4, ir6 := makeIPRanges("127.127.127.127/32", "ffff::/32")
	lbc := &LoadBalancerController{
		ipv4Ranges: ir4,
		ipv6Ranges: ir6,
	}

	svc.Spec.ExternalIPs = append([]string{}, "falafel", "127.127.127.127")
	for _, is := range []string{"ffff::", "aaaa::", "tahini"} {
		ing := v1core.LoadBalancerIngress{
			IP: is,
		}
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, ing)
	}

	addresses4, addresses6 := lbc.getIPsFromService(&svc)
	l4Exp := 1
	l6Exp := 1
	l4 := len(addresses4)
	l6 := len(addresses6)
	if l4 != l4Exp {
		t.Fatalf("expected %d, got %d", l4Exp, l4)
	}
	if l6 != l6Exp {
		t.Fatalf("expected %d, got %d", l6Exp, l6)
	}
}

func TestGetAllocatedIPs(t *testing.T) {
	svcExt := makeTestService()
	svcExt.Spec.ExternalIPs = append([]string{}, "ffff::", "kaka", "255.255.255.255")
	svcLB := makeTestService()
	for _, is := range []string{"aaaa::", "127.127.127.127"} {
		ing := v1core.LoadBalancerIngress{
			IP: is,
		}
		svcLB.Status.LoadBalancer.Ingress = append(svcLB.Status.LoadBalancer.Ingress, ing)
	}

	mi := newMockIndexer(&svcExt, &svcLB, 1234)
	ir4, ir6 := makeIPRanges("127.127.127.127/32", "ffff::/32")
	lbc := &LoadBalancerController{
		ipv4Ranges: ir4,
		ipv6Ranges: ir6,
		svcLister:  mi,
	}

	allocated4, allocated6 := lbc.getAllocatedIPs()

	l4Exp := 1
	l4 := len(allocated4)
	if l4 != l4Exp {
		t.Fatalf("expected %d, got %d", l4Exp, l4)
	}

	l6Exp := 1
	l6 := len(allocated6)
	if l6 != l6Exp {
		t.Fatalf("expected %d, got %d", l6Exp, l6)
	}
}

func TestAppendIngressIP(t *testing.T) {
	svc := makeTestService()
	ip := net.ParseIP("127.127.127.127")
	appendIngressIP(&svc, ip)

	ilExp := 1
	il := len(svc.Status.LoadBalancer.Ingress)
	if ilExp != il {
		t.Fatalf("expected %d, got %d", ilExp, il)
	}

	ipExp := "127.127.127.127"
	if ipExp != svc.Status.LoadBalancer.Ingress[0].IP {
		t.Fatalf("expected %s, got %s", ipExp, svc.Status.LoadBalancer.Ingress[0].IP)
	}
}

func TestAllocateService(t *testing.T) {
	mlbc := &LoadBalancerController{
		clientset: fake.NewSimpleClientset(),
	}
	ir4, ir6 := makeIPRanges("127.127.127.127/30", "ffff::/80")
	mlbc.ipv4Ranges = ir4
	mlbc.ipv6Ranges = ir6
	mi := newMockIndexer()
	mlbc.svcLister = mi
	svc := makeTestService()

	err := mlbc.allocateService(&svc)
	if err != nil {
		t.Fatalf("expected %v, got %s", nil, err)
	}

	svc = makeTestService()
	mlbc.ipv4Ranges = newipRanges(nil)
	fp := v1core.IPFamilyPolicyRequireDualStack
	svc.Spec.IPFamilyPolicy = &fp
	err = mlbc.allocateService(&svc)
	errExp := "unable to allocate dual-stack addresses: no IPs left to allocate"
	if errExp != err.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}

	mlbc.ipv4Ranges = ir4
	mlbc.ipv6Ranges = newipRanges(nil)
	err = mlbc.allocateService(&svc)
	if errExp != err.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}

	mlbc.ipv4Ranges = newipRanges(nil)
	fp = v1core.IPFamilyPolicyPreferDualStack
	svc.Spec.IPFamilyPolicy = &fp
	err = mlbc.allocateService(&svc)
	errExp = "unable to allocate address: no IPs left to allocate"
	if errExp != err.Error() {
		t.Fatalf("expected %s, got %s", errExp, err)
	}

}

type mockInformer struct {
}

func (mf *mockInformer) GetIndexer() cache.Indexer {
	return newMockIndexer()
}

func (mf *mockInformer) AddIndexers(_ cache.Indexers) error {
	return nil
}

func (mf *mockInformer) AddEventHandler(_ cache.ResourceEventHandler) {
}

func (mf *mockInformer) AddEventHandlerWithResyncPeriod(_ cache.ResourceEventHandler, _ time.Duration) {
}

func (mf *mockInformer) GetController() cache.Controller {
	return nil
}

func (mf *mockInformer) GetStore() cache.Store {
	return nil
}

func (mf *mockInformer) HasSynced() bool {
	return false
}

func (mf *mockInformer) LastSyncResourceVersion() string {
	return ""
}

func (mf *mockInformer) Run(_ <-chan struct{}) {
}

func (mf *mockInformer) SetTransform(_ cache.TransformFunc) error {
	return nil
}

func (mf *mockInformer) SetWatchErrorHandler(_ cache.WatchErrorHandler) error {
	return nil
}

func TestNewLoadBalancerController(t *testing.T) {
	t.Setenv("POD_NAMESPACE", testName)
	t.Setenv("POD_NAME", testName)

	mf := &mockInformer{}
	config := &options.KubeRouterConfig{
		LoadBalancerCIDRs: []string{"127.127.127.127/30", "ffff::/80"},
		EnableIPv4:        true,
		EnableIPv6:        true,
	}
	fs := fake.NewSimpleClientset()

	_, err := NewLoadBalancerController(fs, config, mf)
	if err != nil {
		t.Fatalf("expected %v, got %s", nil, err)
	}

	config.EnableIPv4 = false
	_, err = NewLoadBalancerController(fs, config, mf)
	errExp := "IPv4 loadbalancer CIDR specified while IPv4 is disabled"
	if err.Error() != errExp {
		t.Fatalf("expected %s, got %s", errExp, err)
	}

	config.EnableIPv4 = true
	config.EnableIPv6 = false
	_, err = NewLoadBalancerController(fs, config, mf)
	errExp = "IPv6 loadbalancer CIDR specified while IPv6 is disabled"
	if err.Error() != errExp {
		t.Fatalf("expected %s, got %s", errExp, err)
	}
}
