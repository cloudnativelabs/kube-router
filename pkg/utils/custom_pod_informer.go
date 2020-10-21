package utils

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// NewCustomPodInformer is custom controller https://github.com/kubernetes/client-go/blob/master/tools/cache/controller.go
// to provide alternate pod informer https://github.com/kubernetes/client-go/blob/master/informers/core/v1/pod.go
// which persist pod object in the cache with just enough information required for kube-router
func NewCustomPodInformer(client kubernetes.Interface, h cache.ResourceEventHandler) (cache.Indexer, cache.Controller) {
	clientState := cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	lw := cache.NewListWatchFromClient(client.CoreV1().RESTClient(), "pods", v1.NamespaceAll, fields.Everything())
	fifo := cache.NewDeltaFIFO(cache.MetaNamespaceKeyFunc, clientState)
	cfg := &cache.Config{
		Queue:            fifo,
		ListerWatcher:    lw,
		ObjectType:       &v1.Pod{},
		FullResyncPeriod: 0,
		RetryOnError:     false,

		Process: func(obj interface{}) error {
			for _, d := range obj.(cache.Deltas) {
				var obj interface{}
				obj = convertToCustomPod(d.Object)
				switch d.Type {
				case cache.Sync, cache.Added, cache.Updated:
					if old, exists, err := clientState.Get(obj); err == nil && exists {
						if err := clientState.Update(obj); err != nil {
							return err
						}
						h.OnUpdate(old, obj)
					} else {
						if err := clientState.Add(obj); err != nil {
							return err
						}
						h.OnAdd(obj)
					}
				case cache.Deleted:
					if err := clientState.Delete(obj); err != nil {
						return err
					}
					h.OnDelete(obj)
				}
			}
			return nil
		},
	}
	return clientState, cache.New(cfg)
}

// convertToCustomPod stores a stripped down version of pod with just
// enough details needed for kube-router
func convertToCustomPod(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *v1.Pod:
		p := &v1.Pod{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name:            concreteObj.Name,
				Namespace:       concreteObj.Namespace,
				ResourceVersion: concreteObj.ResourceVersion,
			},
			Status: v1.PodStatus{
				Phase:  concreteObj.Status.Phase,
				HostIP: concreteObj.Status.HostIP,
				PodIP:  concreteObj.Status.PodIP,
			},
		}
		*concreteObj = v1.Pod{}
		return p
	case cache.DeletedFinalStateUnknown:
		pod, ok := concreteObj.Obj.(*v1.Pod)
		if !ok {
			return obj
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &v1.Pod{
				TypeMeta: pod.TypeMeta,
				ObjectMeta: metav1.ObjectMeta{
					Name:            pod.Name,
					Namespace:       pod.Namespace,
					ResourceVersion: pod.ResourceVersion,
				},
				Status: v1.PodStatus{
					Phase:  pod.Status.Phase,
					HostIP: pod.Status.HostIP,
					PodIP:  pod.Status.PodIP,
				},
			},
		}
		*pod = v1.Pod{}
		return dfsu
	default:
		return obj
	}
}
