// Copyright 2018 Authors of Cilium
// Modified for integration with kube-router
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helpers

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/cloudnativelabs/kube-router/test/ginkgo-ext"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

// GetCurrentK8SEnv returns the value of K8S_VERSION from the OS environment.
func GetCurrentK8SEnv() string { return os.Getenv("K8S_VERSION") }

// Kubectl is a wrapper around an SSHMeta. It is used to run Kubernetes-specific
// commands on the node which is accessible via the SSH metadata stored in its
// SSHMeta.
type Kubectl struct {
	*SSHMeta
	// *serviceCache
}

// CreateKubectl initializes a Kubectl helper with the provided vmName and log
// It marks the test as Fail if cannot get the ssh meta information or cannot
// execute a `ls` on the virtual machine.
func CreateKubectl(vmName string, log *logrus.Entry) *Kubectl {
	node := GetVagrantSSHMeta(vmName)
	if node == nil {
		ginkgoext.Fail(fmt.Sprintf("Cannot connect to vmName  '%s'", vmName), 1)
		return nil
	}
	// This `ls` command is a sanity check, sometimes the meta ssh info is not
	// nil but new commands cannot be executed using SSH, tests failed and it
	// was hard to debug.
	res := node.Exec("ls /tmp/")
	if !res.WasSuccessful() {
		ginkgoext.Fail(fmt.Sprintf(
			"Cannot execute ls command on vmName '%s'", vmName), 1)
		return nil
	}
	node.logger = log

	return &Kubectl{
		SSHMeta: node,
	}
}

// ExpectAllPodsTerminated is a wrapper around helpers/WaitCleanAllTerminatingPods.
// It asserts that the error returned by that function is nil.
func (k *Kubectl) ExpectAllPodsTerminated() {
	err := k.WaitCleanAllTerminatingPods(HelperTimeout)
	ExpectWithOffset(1, err).To(BeNil(), "terminating containers are not deleted after timeout")
}

// WaitCleanAllTerminatingPods waits until all nodes that are in `Terminating`
// state are deleted correctly in the platform. In case of excedding the
// given timeout (in seconds) it returns an error
func (k *Kubectl) WaitCleanAllTerminatingPods(timeout int64) error {
	body := func() bool {
		res := k.Exec(fmt.Sprintf(
			"%s get pods --all-namespaces -o jsonpath='{.items[*].metadata.deletionTimestamp}'",
			KubectlCmd))
		if !res.WasSuccessful() {
			return false
		}

		if res.Output().String() == "" {
			// Output is empty so no terminating containers
			return true
		}

		podsTerminating := len(strings.Split(res.Output().String(), " "))
		k.logger.WithField("Terminating pods", podsTerminating).Info("List of pods terminating")
		if podsTerminating > 0 {
			return false
		}
		return true
	}

	err := WithTimeout(
		body,
		"Pods are still not deleted after a timeout",
		&TimeoutConfig{Timeout: timeout})
	return err
}

func (k *Kubectl) CreateBusyBoxPod(podName string) error {
	res := k.Exec(fmt.Sprintf("kubectl run -i --tty %s --image=busybox -- sh", podName))
	if !res.WasSuccessful() {
		return res.GetErr("busybox pod creation failed")
	}
	return nil
}

// Apply applies the Kubernetes manifest located at path filepath.
func (k *Kubectl) Apply(filePath string) *CmdRes {
	k.logger.Debugf("applying %s", filePath)
	return k.Exec(
		fmt.Sprintf("%s apply -f  %s", KubectlCmd, filePath))
}

// Create creates the Kubernetes kanifest located at path filepath.
func (k *Kubectl) Create(filePath string) *CmdRes {
	k.logger.Debugf("creating %s", filePath)
	return k.Exec(
		fmt.Sprintf("%s create -f  %s", KubectlCmd, filePath))
}

// CreateResource is a wrapper around `kubernetes create <resource>
// <resourceName>.
func (k *Kubectl) CreateResource(resource, resourceName string) *CmdRes {
	k.logger.Debug(fmt.Sprintf("creating resource %s with name %s", resource, resourceName))
	return k.Exec(fmt.Sprintf("kubectl create %s %s", resource, resourceName))
}

// DeleteResource is a wrapper around `kubernetes delete <resource>
// resourceName>.
func (k *Kubectl) DeleteResource(resource, resourceName string) *CmdRes {
	k.logger.Debug(fmt.Sprintf("deleting resource %s with name %s", resource, resourceName))
	return k.Exec(fmt.Sprintf("kubectl delete %s %s", resource, resourceName))
}

// Delete deletes the Kubernetes manifest at path filepath.
func (k *Kubectl) Delete(filePath string, force bool) *CmdRes {
	k.logger.Debugf("deleting %s", filePath)
	if force {
		return k.Exec(
			fmt.Sprintf("%s delete -f  %s --grace-period=0 --force", KubectlCmd, filePath))
	}
	return k.Exec(
		fmt.Sprintf("%s delete -f  %s", KubectlCmd, filePath))
}

// WaitforPods waits up until timeout seconds have elapsed for all pods in the
// specified namespace that match the provided JSONPath filter to have their
// containterStatuses equal to "ready". Returns true if all pods achieve
// the aforementioned desired state within timeout seconds. Returns false and
// an error if the command failed or the timeout was exceeded.
func (k *Kubectl) WaitforPods(namespace string, filter string, timeout int64) error {
	return k.WaitforNPods(namespace, filter, 0, timeout)
}

// WaitforNPods waits up until timeout seconds have elapsed for at least
// minRequired pods in the specified namespace that match the provided JSONPath
// filter to have their containterStatuses equal to "ready". Returns true if all
// pods achieve the aforementioned desired state within timeout seconds. Returns
// false and an error if the command failed or the timeout was exceeded.
func (k *Kubectl) WaitforNPods(namespace string, filter string, podsRunning int, timeout int64) error {
	data, err := k.GetPods(namespace, filter).Filter("{.items[*].metadata.deletionTimestamp}")
	if err != nil {
		return fmt.Errorf("Cannot get pods with filter '%s': %s", filter, err)
	}
	if data.String() != "" {
		return fmt.Errorf(
			"There are some pods with filter %s that are marked to be deleted", filter)
	}

	body := func() bool {

		var jsonPath = "{.items[*].status.containerStatuses[*].ready}"
		data, err = k.GetPods(namespace, filter).Filter(jsonPath)
		if err != nil {
			k.logger.Errorf("could not get pods: %s", err)
			return false
		}

		valid := 0
		minRequired := podsRunning

		result := strings.Split(data.String(), " ")
		if podsRunning == 0 {
			minRequired = len(result)
		}
		for _, v := range result {
			if val, _ := govalidator.ToBoolean(v); !val {
				break
			}
			valid++
		}
		if valid >= minRequired {
			return true
		}
		k.logger.WithFields(logrus.Fields{
			"namespace":   namespace,
			"filter":      filter,
			"data":        data,
			"valid":       valid,
			"minRequired": minRequired,
		}).Info("WaitforPods: pods are not ready")
		return false
	}
	return WithTimeout(
		body,
		fmt.Sprintf("timed out waiting for pods with filter %s to be ready", filter),
		&TimeoutConfig{Timeout: timeout})
}

// GetPods gets all of the pods in the given namespace that match the provided
// filter.
func (k *Kubectl) GetPods(namespace string, filter string) *CmdRes {
	return k.Exec(fmt.Sprintf("%s -n %s get pods %s -o json", KubectlCmd, namespace, filter))
}

// GetPodsNodes returns a map with pod name as a key and node name as value. It
// only gets pods in the given namespace that match the provided filter. It
// returns an error if pods cannot be retrieved correctly
func (k *Kubectl) GetPodsNodes(namespace string, filter string) (map[string]string, error) {
	jsonFilter := `{range .items[*]}{@.metadata.name}{"="}{@.spec.nodeName}{"\n"}{end}`
	res := k.Exec(fmt.Sprintf("%s -n %s get pods %s -o jsonpath='%s'",
		KubectlCmd, namespace, filter, jsonFilter))
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("cannot retrieve pods: %s", res.CombineOutput())
	}
	return res.KVOutput(), nil
}

// GetPodsIPs returns a map with pod name as a key and pod IP name as value. It
// only gets pods in the given namespace that match the provided filter. It
// returns an error if pods cannot be retrieved correctly
func (k *Kubectl) GetPodsIPs(namespace string, filter string) (map[string]string, error) {
	jsonFilter := `{range .items[*]}{@.metadata.name}{"="}{@.status.podIP}{"\n"}{end}`
	res := k.Exec(fmt.Sprintf("%s -n %s get pods -l %s -o jsonpath='%s'",
		KubectlCmd, namespace, filter, jsonFilter))
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("cannot retrieve pods: %s", res.CombineOutput())
	}
	return res.KVOutput(), nil
}

// GetEndpoints gets all of the endpoints in the given namespace that match the
// provided filter.
func (k *Kubectl) GetEndpoints(namespace string, filter string) *CmdRes {
	return k.Exec(fmt.Sprintf("%s -n %s get endpoints %s -o json", KubectlCmd, namespace, filter))
}

// GetPodNames returns the names of all of the pods that are labeled with label
// in the specified namespace, along with an error if the pod names cannot be
// retrieved.
func (k *Kubectl) GetPodNames(namespace string, label string) ([]string, error) {
	stdout := new(bytes.Buffer)
	filter := "-o jsonpath='{.items[*].metadata.name}'"

	cmd := fmt.Sprintf("%s -n %s get pods -l %s %s", KubectlCmd, namespace, label, filter)

	err := k.ExecuteContext(context.TODO(), cmd, stdout, nil)

	if err != nil {
		return nil, fmt.Errorf(
			"could not find pods in namespace '%v' with label '%v': %s", namespace, label, err)
	}

	out := strings.Trim(stdout.String(), "\n")
	if len(out) == 0 {
		//Small hack. String split always return an array with an empty string
		return []string{}, nil
	}
	return strings.Split(out, " "), nil
}

// GetNodesInternalIPs returns a map with node name as a key and InternalIP as value.
func (k *Kubectl) GetNodesInternalIPs() (map[string]string, error) {
	// kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}'
	jsonFilter := `{range .items[*]}{@.metadata.name}{"="}{@.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}`
	res := k.Exec(fmt.Sprintf("%s get nodes -o jsonpath='%s'",
		KubectlCmd, jsonFilter))
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("cannot retrieve nodes: %s", res.CombineOutput())
	}
	return res.KVOutput(), nil
}

// Logs returns a CmdRes with containing the resulting metadata from the
// execution of `kubectl logs <pod> -n <namespace>`.
func (k *Kubectl) Logs(namespace string, pod string) *CmdRes {
	return k.Exec(
		fmt.Sprintf("%s -n %s logs %s", KubectlCmd, namespace, pod))
}

// ExecPodCmd executes command cmd in the specified pod residing in the specified
// namespace. It returns a pointer to CmdRes with all the output
func (k *Kubectl) ExecPodCmd(namespace string, pod string, cmd string, options ...ExecOptions) *CmdRes {
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
	return k.Exec(command, options...)
}

// ExecPodCmdContext executes command cmd in background in the specified pod residing
// in the specified namespace. It returns a pointer to CmdRes with all the
// output
func (k *Kubectl) ExecPodCmdContext(ctx context.Context, namespace string, pod string, cmd string) *CmdRes {
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
	return k.ExecInBackground(ctx, command)
}
