package watchers

import (
	"reflect"
	"time"

	"github.com/cloudnativelabs/kube-router/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	api "k8s.io/client-go/pkg/api/v1"
	cache "k8s.io/client-go/tools/cache"
)

type NamespaceUpdate struct {
	Namespace *api.Namespace
	Op        Operation
}

var (
	NamespaceWatcher *namespaceWatcher
	namespaceStopCh  chan struct{}
)

type namespaceWatcher struct {
	clientset           *kubernetes.Clientset
	namespaceController cache.Controller
	namespaceLister     cache.Indexer
	broadcaster         *utils.Broadcaster
}

type NamespaceUpdatesHandler interface {
	OnNamespaceUpdate(namespaceUpdate *NamespaceUpdate)
}

func (nsw *namespaceWatcher) namespaceAddEventHandler(obj interface{}) {
	namespace, ok := obj.(*api.Namespace)
	if !ok {
		return
	}
	nsw.broadcaster.Notify(&NamespaceUpdate{Op: ADD, Namespace: namespace})
}

func (nsw *namespaceWatcher) namespaceDeleteEventHandler(obj interface{}) {
	namespace, ok := obj.(*api.Namespace)
	if !ok {
		return
	}
	nsw.broadcaster.Notify(&NamespaceUpdate{Op: REMOVE, Namespace: namespace})
}

func (nsw *namespaceWatcher) namespaceUpdateEventHandler(oldObj, newObj interface{}) {
	namespace, ok := newObj.(*api.Namespace)
	if !ok {
		return
	}
	if !reflect.DeepEqual(newObj, oldObj) {
		nsw.broadcaster.Notify(&NamespaceUpdate{Op: UPDATE, Namespace: namespace})
	}
}

func (nsw *namespaceWatcher) List() []*api.Namespace {
	obj_list := nsw.namespaceLister.List()
	namespace_instances := make([]*api.Namespace, len(obj_list))
	for i, ins := range obj_list {
		namespace_instances[i] = ins.(*api.Namespace)
	}
	return namespace_instances
}

func (nsw *namespaceWatcher) RegisterHandler(handler NamespaceUpdatesHandler) {
	nsw.broadcaster.Add(utils.ListenerFunc(func(instance interface{}) {
		handler.OnNamespaceUpdate(instance.(*NamespaceUpdate))
	}))
}

func StartNamespaceWatcher(clientset *kubernetes.Clientset, resyncPeriod time.Duration) (*namespaceWatcher, error) {

	nsw := namespaceWatcher{}
	NamespaceWatcher = &nsw
	eventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    nsw.namespaceAddEventHandler,
		DeleteFunc: nsw.namespaceDeleteEventHandler,
		UpdateFunc: nsw.namespaceUpdateEventHandler,
	}

	nsw.clientset = clientset
	nsw.broadcaster = utils.NewBroadcaster()
	lw := cache.NewListWatchFromClient(clientset.Core().RESTClient(), "namespaces", metav1.NamespaceAll, fields.Everything())
	nsw.namespaceLister, nsw.namespaceController = cache.NewIndexerInformer(
		lw,
		&api.Namespace{}, resyncPeriod, eventHandler,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	namespaceStopCh = make(chan struct{})
	go nsw.namespaceController.Run(namespaceStopCh)
	return &nsw, nil
}

func StopNamespaceWatcher() {
	namespaceStopCh <- struct{}{}
}
