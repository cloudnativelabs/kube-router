package watchers

import (
	"time"

	"github.com/cloudnativelabs/kube-router/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	api "k8s.io/client-go/pkg/api/v1"
	cache "k8s.io/client-go/tools/cache"
)

type NodeUpdate struct {
	Node *api.Node
	Op   Operation
}

var (
	NodeWatcher *nodeWatcher
)

type nodeWatcher struct {
	clientset      *kubernetes.Clientset
	nodeController cache.Controller
	nodeLister     cache.Indexer
	broadcaster    *utils.Broadcaster
}

type NodeUpdatesHandler interface {
	OnNodeUpdate(nodeUpdate *NodeUpdate)
}

func (nw *nodeWatcher) nodeAddEventHandler(obj interface{}) {
	node, ok := obj.(*api.Node)
	if !ok {
		return
	}
	nw.broadcaster.Notify(&NodeUpdate{Op: ADD, Node: node})
}

func (nw *nodeWatcher) nodeDeleteEventHandler(obj interface{}) {
	node, ok := obj.(*api.Node)
	if !ok {
		return
	}
	nw.broadcaster.Notify(&NodeUpdate{Op: REMOVE, Node: node})
}

func (nw *nodeWatcher) nodeUpdateEventHandler(oldObj, newObj interface{}) {
	// we are interested only node add/delete, so skip update
	return
}

func (nw *nodeWatcher) RegisterHandler(handler NodeUpdatesHandler) {
	nw.broadcaster.Add(utils.ListenerFunc(func(instance interface{}) {
		handler.OnNodeUpdate(instance.(*NodeUpdate))
	}))
}

func (nw *nodeWatcher) List() []*api.Node {
	obj_list := nw.nodeLister.List()
	node_instances := make([]*api.Node, len(obj_list))
	for i, ins := range obj_list {
		node_instances[i] = ins.(*api.Node)
	}
	return node_instances
}

func (nw *nodeWatcher) HasSynced() bool {
	return nw.nodeController.HasSynced()
}

var nodewatchStopCh chan struct{}

func StartNodeWatcher(clientset *kubernetes.Clientset, resyncPeriod time.Duration) (*nodeWatcher, error) {

	nw := nodeWatcher{}
	NodeWatcher = &nw
	eventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    nw.nodeAddEventHandler,
		DeleteFunc: nw.nodeDeleteEventHandler,
		UpdateFunc: nw.nodeUpdateEventHandler,
	}

	nw.clientset = clientset
	nw.broadcaster = utils.NewBroadcaster()
	lw := cache.NewListWatchFromClient(clientset.Core().RESTClient(), "nodes", metav1.NamespaceAll, fields.Everything())
	nw.nodeLister, nw.nodeController = cache.NewIndexerInformer(
		lw,
		&api.Node{}, resyncPeriod, eventHandler,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	nodewatchStopCh = make(chan struct{})
	go nw.nodeController.Run(nodewatchStopCh)
	return &nw, nil
}

func StopNodeWatcher() {
	nodewatchStopCh <- struct{}{}
}
