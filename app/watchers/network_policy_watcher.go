package watchers

import (
	"reflect"
	"strconv"
	"time"
	"errors"

	"github.com/cloudnativelabs/kube-router/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	apiextensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	networking "k8s.io/client-go/pkg/apis/networking/v1"
	cache "k8s.io/client-go/tools/cache"
)

type NetworkPolicyUpdate struct {
	NetworkPolicy interface{}
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
	npw.broadcaster.Notify(&NetworkPolicyUpdate{Op: ADD, NetworkPolicy: obj})
}

func (npw *networkPolicyWatcher) networkPolicyDeleteEventHandler(obj interface{}) {
	npw.broadcaster.Notify(&NetworkPolicyUpdate{Op: REMOVE, NetworkPolicy: obj})
}

func (npw *networkPolicyWatcher) networkPolicyUpdateEventHandler(oldObj, newObj interface{}) {
	if !reflect.DeepEqual(newObj, oldObj) {
		npw.broadcaster.Notify(&NetworkPolicyUpdate{Op: UPDATE, NetworkPolicy: newObj})
	}
}

func (npw *networkPolicyWatcher) RegisterHandler(handler NetworkPolicyUpdatesHandler) {
	npw.broadcaster.Add(utils.ListenerFunc(func(instance interface{}) {
		handler.OnNetworkPolicyUpdate(instance.(*NetworkPolicyUpdate))
	}))
}

func (npw *networkPolicyWatcher) List() []interface{} {
	return npw.networkPolicyLister.List()
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

	v1NetworkPolicy := true
	v, err := clientset.Discovery().ServerVersion()
	if err != nil {
       return nil, errors.New("Failed to get API server version due to " + err.Error()) 
	}

	minorVer, _ := strconv.Atoi(v.Minor)
	if v.Major == "1" && minorVer < 7 {
		v1NetworkPolicy = false
	}

	npw.broadcaster = utils.NewBroadcaster()
	var lw *cache.ListWatch
	if v1NetworkPolicy {
		lw = cache.NewListWatchFromClient(clientset.Networking().RESTClient(), "networkpolicies", metav1.NamespaceAll, fields.Everything())
		npw.networkPolicyLister, npw.networkPolicyController = cache.NewIndexerInformer(
			lw, &networking.NetworkPolicy{}, resyncPeriod, eventHandler,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	} else {
		lw = cache.NewListWatchFromClient(clientset.Extensions().RESTClient(), "networkpolicies", metav1.NamespaceAll, fields.Everything())
		npw.networkPolicyLister, npw.networkPolicyController = cache.NewIndexerInformer(
			lw, &apiextensions.NetworkPolicy{}, resyncPeriod, eventHandler,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}
	networkPolicyStopCh = make(chan struct{})
	go npw.networkPolicyController.Run(networkPolicyStopCh)
	return &npw, nil
}

func StopNetworkPolicyWatcher() {
	networkPolicyStopCh <- struct{}{}
}
