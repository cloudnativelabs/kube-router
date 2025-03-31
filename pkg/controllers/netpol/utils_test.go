package netpol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	fakePod = api.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testpod",
			Namespace: "testnamespace",
			Labels:    map[string]string{"foo": "bar"}},
		Spec: api.PodSpec{
			Containers: []api.Container{
				{
					Image: "k8s.gcr.io/busybox",
				},
			},
		},
		Status: api.PodStatus{
			PodIP: "172.16.0.1",
			PodIPs: []api.PodIP{
				{
					IP: "172.16.0.1",
				},
			},
			HostIP: "10.0.0.1",
			Phase:  api.PodRunning,
		},
	}
)

func Test_isPodUpdateNetPolRelevant(t *testing.T) {
	t.Run("Pod phase change should be detected as NetworkPolicy relevant", func(t *testing.T) {
		newPod := fakePod.DeepCopy()
		newPod.Status.Phase = api.PodFailed
		assert.True(t, isPodUpdateNetPolRelevant(&fakePod, newPod))
	})
	t.Run("Pod IP change should be detected as NetworkPolicy relevant", func(t *testing.T) {
		newPod := fakePod.DeepCopy()
		newPod.Status.PodIP = "172.16.0.2"
		assert.True(t, isPodUpdateNetPolRelevant(&fakePod, newPod))
	})
	t.Run("Pod IPs change should be detected as NetworkPolicy relevant", func(t *testing.T) {
		newPod := fakePod.DeepCopy()
		newPod.Status.PodIPs = []api.PodIP{{IP: "172.16.0.2"}}
		assert.True(t, isPodUpdateNetPolRelevant(&fakePod, newPod))
	})
	t.Run("Pod Label change should be detected as NetworkPolicy relevant", func(t *testing.T) {
		newPod := fakePod.DeepCopy()
		newPod.Labels = map[string]string{"bar": "foo"}
		assert.True(t, isPodUpdateNetPolRelevant(&fakePod, newPod))
	})
	t.Run("Pod Host IP change should be detected as NetworkPolicy relevant", func(t *testing.T) {
		newPod := fakePod.DeepCopy()
		newPod.Status.HostIP = "10.0.0.2"
		assert.True(t, isPodUpdateNetPolRelevant(&fakePod, newPod))
	})
	t.Run("Pod Image change should NOT be detected as NetworkPolicy relevant", func(t *testing.T) {
		newPod := fakePod.DeepCopy()
		newPod.Spec.Containers[0].Image = "k8s.gcr.io/otherimage"
		assert.False(t, isPodUpdateNetPolRelevant(&fakePod, newPod))
	})
	t.Run("Pod Name change should NOT be detected as NetworkPolicy relevant", func(t *testing.T) {
		newPod := fakePod.DeepCopy()
		newPod.Name = "otherpod"
		assert.False(t, isPodUpdateNetPolRelevant(&fakePod, newPod))
	})
}

func Test_isPodFinished(t *testing.T) {
	t.Run("Failed pod should be detected as finished", func(t *testing.T) {
		fakePod.Status.Phase = api.PodFailed
		assert.True(t, isFinished(&fakePod))
	})
	t.Run("Succeeded pod should be detected as finished", func(t *testing.T) {
		fakePod.Status.Phase = api.PodSucceeded
		assert.True(t, isFinished(&fakePod))
	})
	t.Run("Completed pod should be detected as finished", func(t *testing.T) {
		fakePod.Status.Phase = PodCompleted
		assert.True(t, isFinished(&fakePod))
	})
	t.Run("Running pod should NOT be detected as finished", func(t *testing.T) {
		fakePod.Status.Phase = api.PodRunning
		assert.False(t, isFinished(&fakePod))
	})
	t.Run("Pending pod should NOT be detected as finished", func(t *testing.T) {
		fakePod.Status.Phase = api.PodPending
		assert.False(t, isFinished(&fakePod))
	})
	t.Run("Unknown pod should NOT be detected as finished", func(t *testing.T) {
		fakePod.Status.Phase = api.PodUnknown
		assert.False(t, isFinished(&fakePod))
	})
}

func Test_isNetPolActionable(t *testing.T) {
	t.Run("Normal pod should be actionable", func(t *testing.T) {
		assert.True(t, isNetPolActionable(&fakePod))
	})
	t.Run("Pod without Pod IP should not be actionable", func(t *testing.T) {
		fakePod.Status.PodIP = ""
		assert.False(t, isNetPolActionable(&fakePod))
	})
	t.Run("Finished Pod should not be actionable", func(t *testing.T) {
		fakePod.Status.Phase = api.PodFailed
		assert.False(t, isNetPolActionable(&fakePod))
		fakePod.Status.Phase = api.PodSucceeded
		assert.False(t, isNetPolActionable(&fakePod))
		fakePod.Status.Phase = PodCompleted
		assert.False(t, isNetPolActionable(&fakePod))
	})
	t.Run("Host Networked Pod should not be actionable", func(t *testing.T) {
		fakePod.Spec.HostNetwork = true
		assert.False(t, isNetPolActionable(&fakePod))
	})
}

func Test_NewNetworkPolicyController(t *testing.T) {
	t.Run("Node Port range specified with a hyphen should pass validation", func(t *testing.T) {
		portRange, err := validateNodePortRange("1000-2000")
		assert.Nil(t, err)
		assert.NotEmpty(t, portRange)
	})
	t.Run("Node Port range specified with a colon should pass validation", func(t *testing.T) {
		portRange, err := validateNodePortRange("1000:2000")
		assert.Nil(t, err)
		assert.NotEmpty(t, portRange)
	})
	t.Run("Node Port range specified with a high port range should work", func(t *testing.T) {
		portRange, err := validateNodePortRange("40000:42767")
		assert.Nil(t, err)
		assert.NotEmpty(t, portRange)
		portRange, err = validateNodePortRange("50000:65535")
		assert.Nil(t, err)
		assert.NotEmpty(t, portRange)
	})
	t.Run("Node Port range specified with a higher start number should fail validation", func(t *testing.T) {
		portRange, err := validateNodePortRange("2000:1000")
		assert.Error(t, err)
		assert.Empty(t, portRange)
	})
	t.Run("Node Port range specified with same start and end port should fail validation", func(t *testing.T) {
		portRange, err := validateNodePortRange("2000:2000")
		assert.Error(t, err)
		assert.Empty(t, portRange)
	})
	t.Run("Node Port range specified with a port number higher than 16-bits unsigned should fail validation", func(t *testing.T) {
		portRange, err := validateNodePortRange("65535:65537")
		assert.Error(t, err)
		assert.Empty(t, portRange)
	})
}
