package watchers

import (
	"reflect"
	"time"

	"github.com/cloudnativelabs/kube-router/utils"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

type PodUpdate struct {
	Pod *api.Pod
	Op  Operation
}

var (
	PodWatcher *podWatcher
)

type podWatcher struct {
	clientset     *kubernetes.Clientset
	podController cache.Controller
	podLister     cache.Indexer
	broadcaster   *utils.Broadcaster
}

type PodUpdatesHandler interface {
	OnPodUpdate(podUpdate *PodUpdate)
}

func (pw *podWatcher) podAddEventHandler(obj interface{}) {
	pod, ok := obj.(*api.Pod)
	if !ok {
		return
	}
	pw.broadcaster.Notify(&PodUpdate{Op: ADD, Pod: pod})
}

func (pw *podWatcher) podDeleteEventHandler(obj interface{}) {
	pod, ok := obj.(*api.Pod)
	if !ok {
		return
	}
	pw.broadcaster.Notify(&PodUpdate{Op: REMOVE, Pod: pod})
}

func (pw *podWatcher) podAUpdateEventHandler(oldObj, newObj interface{}) {
	pod, ok := newObj.(*api.Pod)
	if !ok {
		return
	}
	if !reflect.DeepEqual(newObj, oldObj) {
		pw.broadcaster.Notify(&PodUpdate{Op: UPDATE, Pod: pod})
	}
}

func (pw *podWatcher) RegisterHandler(handler PodUpdatesHandler) {
	pw.broadcaster.Add(utils.ListenerFunc(func(instance interface{}) {
		handler.OnPodUpdate(instance.(*PodUpdate))
	}))
}

func (pw *podWatcher) List() []*api.Pod {
	objList := pw.podLister.List()
	podInstances := make([]*api.Pod, len(objList))
	for i, ins := range objList {
		podInstances[i] = ins.(*api.Pod)
	}
	return podInstances
}

func (pw *podWatcher) ListByNamespaceAndLabels(namespace string, labelsToMatch labels.Set) (ret []*api.Pod, err error) {
	podLister := listers.NewPodLister(pw.podLister)
	allMatchedNameSpacePods, err := podLister.Pods(namespace).List(labelsToMatch.AsSelector())
	if err != nil {
		return nil, err
	}
	return allMatchedNameSpacePods, nil
}

func (pw *podWatcher) HasSynced() bool {
	return pw.podController.HasSynced()
}

var podwatchStopCh chan struct{}

func StartPodWatcher(clientset *kubernetes.Clientset, resyncPeriod time.Duration) (*podWatcher, error) {

	pw := podWatcher{}
	PodWatcher = &pw
	eventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    pw.podAddEventHandler,
		DeleteFunc: pw.podDeleteEventHandler,
		UpdateFunc: pw.podAUpdateEventHandler,
	}

	pw.clientset = clientset
	pw.broadcaster = utils.NewBroadcaster()
	lw := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", metav1.NamespaceAll, fields.Everything())
	pw.podLister, pw.podController = cache.NewIndexerInformer(
		lw,
		&api.Pod{}, resyncPeriod, eventHandler,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	podwatchStopCh = make(chan struct{})
	go pw.podController.Run(podwatchStopCh)
	return &pw, nil
}

func StopPodWatcher() {
	podwatchStopCh <- struct{}{}
}
