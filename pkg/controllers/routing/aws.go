package routing

import (
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// disableSourceDestinationCheck disables src-dst check of all the VM's when cluster
// is provisioned on AWS. EC2 by default drops any packets originating or destination
// to a VM with IP other than that of VM's ip. This check needs to be disabled so that
// cross node pod-to-pod traffic can be sent and recived by a VM.
func (nrc *NetworkRoutingController) disableSourceDestinationCheck() {
	nodes, err := nrc.clientset.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		glog.Errorf("Failed to list nodes from API server due to: %s. Cannot perform BGP peer sync", err.Error())
		return
	}

	for _, node := range nodes.Items {
		if node.Spec.ProviderID == "" || !strings.HasPrefix(node.Spec.ProviderID, "aws") {
			return
		}
		providerID := strings.Replace(node.Spec.ProviderID, "///", "//", 1)
		URL, err := url.Parse(providerID)
		instanceID := URL.Path
		instanceID = strings.Trim(instanceID, "/")

		sess, _ := session.NewSession(aws.NewConfig().WithMaxRetries(5))
		metadataClient := ec2metadata.New(sess)
		region, err := metadataClient.Region()
		if err != nil {
			glog.Errorf("Failed to disable source destination check due to: " + err.Error())
			return
		}
		sess.Config.Region = aws.String(region)
		ec2Client := ec2.New(sess)
		_, err = ec2Client.ModifyInstanceAttribute(
			&ec2.ModifyInstanceAttributeInput{
				InstanceId: aws.String(instanceID),
				SourceDestCheck: &ec2.AttributeBooleanValue{
					Value: aws.Bool(false),
				},
			},
		)
		if err != nil {
			awserr := err.(awserr.Error)
			if awserr.Code() == "UnauthorizedOperation" {
				nrc.ec2IamAuthorized = false
				glog.Errorf("Node does not have necessary IAM creds to modify instance attribute. So skipping disabling src-dst check.")
				return
			}
			glog.Errorf("Failed to disable source destination check due to: %v", err.Error())
		} else {
			glog.Infof("Disabled source destination check for the instance: " + instanceID)
		}

		// to prevent EC2 rejecting API call due to API throttling give a delay between the calls
		time.Sleep(1000 * time.Millisecond)
	}
}
