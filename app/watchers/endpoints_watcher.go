package watchers

import (
	"reflect"
	"time"

	"github.com/cloudnativelabs/kube-router/utils"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type Operation int

const (
	ADD Operation = iota
	UPDATE
	REMOVE
	SYNCED
)

type EndpointsUpdate struct {
	Endpoints *api.Endpoints
	Op        Operation
}

var (
	EndpointsWatcher *endpointsWatcher
)

type endpointsWatcher struct {
	clientset           *kubernetes.Clientset
	endpointsController cache.Controller
	endpointsLister     cache.Indexer
	broadcaster         *utils.Broadcaster
}

type EndpointsUpdatesHandler interface {
	OnEndpointsUpdate(endpointsUpdate *EndpointsUpdate)
}

func (ew *endpointsWatcher) endpointsAddEventHandler(obj interface{}) {
	endpoints, ok := obj.(*api.Endpoints)
	if !ok {
		return
	}
	ew.broadcaster.Notify(&EndpointsUpdate{Op: ADD, Endpoints: endpoints})
}

func (ew *endpointsWatcher) endpointsDeleteEventHandler(obj interface{}) {
	endpoints, ok := obj.(*api.Endpoints)
	if !ok {
		return
	}
	ew.broadcaster.Notify(&EndpointsUpdate{Op: REMOVE, Endpoints: endpoints})
}

func (ew *endpointsWatcher) endpointsUpdateEventHandler(oldObj, newObj interface{}) {
	endpoints, ok := newObj.(*api.Endpoints)
	if !ok {
		return
	}
	if !reflect.DeepEqual(newObj, oldObj) {
		if endpoints.Name != "kube-scheduler" && endpoints.Name != "kube-controller-manager" {
			ew.broadcaster.Notify(&EndpointsUpdate{Op: UPDATE, Endpoints: endpoints})
		}
	}
}

func (ew *endpointsWatcher) RegisterHandler(handler EndpointsUpdatesHandler) {
	ew.broadcaster.Add(utils.ListenerFunc(func(instance interface{}) {
		handler.OnEndpointsUpdate(instance.(*EndpointsUpdate))
	}))
}

func (ew *endpointsWatcher) List() []*api.Endpoints {
	objList := ew.endpointsLister.List()
	epInstances := make([]*api.Endpoints, len(objList))
	for i, ins := range objList {
		epInstances[i] = ins.(*api.Endpoints)
	}
	return epInstances
}

func (ew *endpointsWatcher) HasSynced() bool {
	return ew.endpointsController.HasSynced()
}

var endpointsStopCh chan struct{}

func StartEndpointsWatcher(clientset *kubernetes.Clientset, resyncPeriod time.Duration) (*endpointsWatcher, error) {

	ew := endpointsWatcher{}
	EndpointsWatcher = &ew

	eventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    ew.endpointsAddEventHandler,
		DeleteFunc: ew.endpointsDeleteEventHandler,
		UpdateFunc: ew.endpointsUpdateEventHandler,
	}

	ew.clientset = clientset
	ew.broadcaster = utils.NewBroadcaster()
	lw := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "endpoints", metav1.NamespaceAll, fields.Everything())
	ew.endpointsLister, ew.endpointsController = cache.NewIndexerInformer(
		lw,
		&api.Endpoints{}, resyncPeriod, eventHandler,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	endpointsStopCh = make(chan struct{})
	go ew.endpointsController.Run(endpointsStopCh)
	return &ew, nil
}

func StopEndpointsWatcher() {
	endpointsStopCh <- struct{}{}
}
