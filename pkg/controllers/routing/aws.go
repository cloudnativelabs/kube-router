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
	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
)

const (
	awsThrottlingRequestDelay = 1000 * time.Millisecond
	awsMaxRetries             = 5
)

// disableSourceDestinationCheck disables src-dst check of all the VM's when cluster
// is provisioned on AWS. EC2 by default drops any packets originating or destination
// to a VM with IP other than that of VM's ip. This check needs to be disabled so that
// cross node pod-to-pod traffic can be sent and received by a VM.
func (nrc *NetworkRoutingController) disableSourceDestinationCheck() {
	nodes := nrc.nodeLister.List()

	for _, obj := range nodes {
		node := obj.(*corev1.Node)
		if node.Spec.ProviderID == "" || !strings.HasPrefix(node.Spec.ProviderID, "aws") {
			return
		}
		providerID := strings.Replace(node.Spec.ProviderID, "///", "//", 1)
		URL, err := url.Parse(providerID)
		if err != nil {
			klog.Errorf("Failed to parse URL for providerID " + providerID + " : " + err.Error())
			return
		}
		instanceID := URL.Path
		instanceID = strings.Trim(instanceID, "/")

		sess, _ := session.NewSession(aws.NewConfig().WithMaxRetries(awsMaxRetries))
		metadataClient := ec2metadata.New(sess)
		region, err := metadataClient.Region()
		if err != nil {
			klog.Errorf("Failed to disable source destination check due to: " + err.Error())
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
			awsErr := err.(awserr.Error)
			if awsErr.Code() == "UnauthorizedOperation" {
				nrc.ec2IamAuthorized = false
				klog.Errorf("Node does not have necessary IAM creds to modify instance attribute. So skipping " +
					"disabling src-dst check.")
				return
			}
			klog.Errorf("Failed to disable source destination check due to: %v", err.Error())
		} else {
			klog.Infof("Disabled source destination check for the instance: " + instanceID)
		}

		// to prevent EC2 rejecting API call due to API throttling give a delay between the calls
		time.Sleep(awsThrottlingRequestDelay)
	}
}
