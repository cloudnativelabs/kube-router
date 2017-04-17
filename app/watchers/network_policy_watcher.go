package watchers

import (
	"reflect"
	"time"

	"github.com/cloudnativelabs/kube-router/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	apiextensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	cache "k8s.io/client-go/tools/cache"
)

type NetworkPolicyUpdate struct {
	NetworkPolicy *apiextensions.NetworkPolicy
	Op            Operation
}

var (
	NetworkPolicyWatcher *networkPolicyWatcher
)

type networkPolicyWatcher struct {
	clientset               *kubernetes.Clientset
	networkPolicyController cache.Controller
	networkPolicyLister     cache.Indexer
	broadcaster             *utils.Broadcaster
}

type NetworkPolicyUpdatesHandler interface {
	OnNetworkPolicyUpdate(networkPolicyUpdate *NetworkPolicyUpdate)
}

func (npw *networkPolicyWatcher) networkPolicyAddEventHandler(obj interface{}) {
	policy, ok := obj.(*apiextensions.NetworkPolicy)
	if !ok {
		return
	}
	npw.broadcaster.Notify(&NetworkPolicyUpdate{Op: ADD, NetworkPolicy: policy})
}

func (npw *networkPolicyWatcher) networkPolicyDeleteEventHandler(obj interface{}) {
	policy, ok := obj.(*apiextensions.NetworkPolicy)
	if !ok {
		return
	}
	npw.broadcaster.Notify(&NetworkPolicyUpdate{Op: REMOVE, NetworkPolicy: policy})
}

func (npw *networkPolicyWatcher) networkPolicyUpdateEventHandler(oldObj, newObj interface{}) {
	policy, ok := newObj.(*apiextensions.NetworkPolicy)
	if !ok {
		return
	}
	if !reflect.DeepEqual(newObj, oldObj) {
		npw.broadcaster.Notify(&NetworkPolicyUpdate{Op: UPDATE, NetworkPolicy: policy})
	}
}

func (npw *networkPolicyWatcher) RegisterHandler(handler NetworkPolicyUpdatesHandler) {
	npw.broadcaster.Add(utils.ListenerFunc(func(instance interface{}) {
		handler.OnNetworkPolicyUpdate(instance.(*NetworkPolicyUpdate))
	}))
}

func (npw *networkPolicyWatcher) List() []*apiextensions.NetworkPolicy {
	obj_list := npw.networkPolicyLister.List()
	np_instances := make([]*apiextensions.NetworkPolicy, len(obj_list))
	for i, ins := range obj_list {
		np_instances[i] = ins.(*apiextensions.NetworkPolicy)
	}
	return np_instances
}

func (npw *networkPolicyWatcher) HasSynced() bool {
	return npw.networkPolicyController.HasSynced()
}

var networkPolicyStopCh chan struct{}

func StartNetworkPolicyWatcher(clientset *kubernetes.Clientset, resyncPeriod time.Duration) (*networkPolicyWatcher, error) {

	npw := networkPolicyWatcher{}
	NetworkPolicyWatcher = &npw

	eventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    npw.networkPolicyAddEventHandler,
		DeleteFunc: npw.networkPolicyDeleteEventHandler,
		UpdateFunc: npw.networkPolicyUpdateEventHandler,
	}

	npw.clientset = clientset
	npw.broadcaster = utils.NewBroadcaster()
	lw := cache.NewListWatchFromClient(clientset.Extensions().RESTClient(), "networkpolicies", metav1.NamespaceAll, fields.Everything())
	npw.networkPolicyLister, npw.networkPolicyController = cache.NewIndexerInformer(
		lw,
		&apiextensions.NetworkPolicy{}, resyncPeriod, eventHandler,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	networkPolicyStopCh = make(chan struct{})
	go npw.networkPolicyController.Run(networkPolicyStopCh)
	return &npw, nil
}

func StopNetworkPolicyWatcher() {
	networkPolicyStopCh <- struct{}{}
}
