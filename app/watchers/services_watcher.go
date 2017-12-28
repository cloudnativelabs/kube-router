package watchers

import (
	"reflect"
	"time"

	"github.com/cloudnativelabs/kube-router/utils"

	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type ServiceUpdate struct {
	Service *api.Service
	Op      Operation
}

var (
	ServiceWatcher *serviceWatcher
)

type serviceWatcher struct {
	clientset         kubernetes.Interface
	serviceController cache.Controller
	serviceLister     cache.Indexer
	broadcaster       *utils.Broadcaster
}

type ServiceUpdatesHandler interface {
	OnServiceUpdate(serviceUpdate *ServiceUpdate)
}

func (svcw *serviceWatcher) serviceAddEventHandler(obj interface{}) {
	service, ok := obj.(*api.Service)
	if !ok {
		return
	}
	svcw.broadcaster.Notify(&ServiceUpdate{Op: ADD, Service: service})
}

func (svcw *serviceWatcher) serviceDeleteEventHandler(obj interface{}) {
	service, ok := obj.(*api.Service)
	if !ok {
		return
	}
	svcw.broadcaster.Notify(&ServiceUpdate{Op: REMOVE, Service: service})
}

func (svcw *serviceWatcher) serviceAUpdateEventHandler(oldObj, newObj interface{}) {
	service, ok := newObj.(*api.Service)
	if !ok {
		return
	}
	if !reflect.DeepEqual(newObj, oldObj) {
		svcw.broadcaster.Notify(&ServiceUpdate{Op: UPDATE, Service: service})
	}
}

func (svcw *serviceWatcher) RegisterHandler(handler ServiceUpdatesHandler) {
	svcw.broadcaster.Add(utils.ListenerFunc(func(instance interface{}) {
		handler.OnServiceUpdate(instance.(*ServiceUpdate))
	}))
}

func (svcw *serviceWatcher) List() []*api.Service {
	objList := svcw.serviceLister.List()
	svcInstances := make([]*api.Service, len(objList))
	for i, ins := range objList {
		svcInstances[i] = ins.(*api.Service)
	}
	return svcInstances
}

func (svcw *serviceWatcher) HasSynced() bool {
	return svcw.serviceController.HasSynced()
}

var servicesStopCh chan struct{}

// StartServiceWatcher: start watching updates for services from Kuberentes API server
func StartServiceWatcher(clientset kubernetes.Interface, resyncPeriod time.Duration) (*serviceWatcher, error) {

	svcw := serviceWatcher{}
	ServiceWatcher = &svcw

	eventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    svcw.serviceAddEventHandler,
		DeleteFunc: svcw.serviceDeleteEventHandler,
		UpdateFunc: svcw.serviceAUpdateEventHandler,
	}

	svcw.clientset = clientset
	svcw.broadcaster = utils.NewBroadcaster()
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return clientset.CoreV1().Services(metav1.NamespaceAll).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return clientset.CoreV1().Services(metav1.NamespaceAll).Watch(options)
		},
	}

	svcw.serviceLister, svcw.serviceController = cache.NewIndexerInformer(
		lw,
		&api.Service{}, resyncPeriod, eventHandler,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	servicesStopCh = make(chan struct{})
	go svcw.serviceController.Run(servicesStopCh)
	return &svcw, nil
}
func StopServiceWatcher() {
	servicesStopCh <- struct{}{}
}
