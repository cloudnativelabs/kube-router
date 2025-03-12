package routing

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"k8s.io/klog/v2"

	v1core "k8s.io/api/core/v1"
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
		node := obj.(*v1core.Node)
		if node.Spec.ProviderID == "" || !strings.HasPrefix(node.Spec.ProviderID, "aws") {
			return
		}
		providerID := strings.Replace(node.Spec.ProviderID, "///", "//", 1)
		URL, err := url.Parse(providerID)
		if err != nil {
			klog.Errorf("failed to parse URL for providerID %s: %v", providerID, err)
			return
		}
		instanceID := URL.Path
		instanceID = strings.Trim(instanceID, "/")

		cfg, _ := config.LoadDefaultConfig(context.TODO(),
			config.WithRetryMaxAttempts(awsMaxRetries))
		metadataClient := imds.NewFromConfig(cfg)
		region, err := metadataClient.GetRegion(context.TODO(), &imds.GetRegionInput{})
		if err != nil {
			klog.Errorf("failed to disable source destination check due to: %v", err)
			return
		}
		cfg.Region = region.Region
		ec2Client := ec2.NewFromConfig(cfg)
		_, err = ec2Client.ModifyInstanceAttribute(context.TODO(),
			&ec2.ModifyInstanceAttributeInput{
				InstanceId: aws.String(instanceID),
				SourceDestCheck: &types.AttributeBooleanValue{
					Value: aws.Bool(false),
				},
			},
		)
		if err != nil {
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) {
				if apiErr.ErrorCode() == "UnauthorizedOperation" {
					nrc.ec2IamAuthorized = false
					klog.Errorf("Node does not have necessary IAM creds to modify instance attribute. So skipping "+
						"disabling src-dst check. %v", apiErr.ErrorMessage())
					return

				}
			}
			klog.Errorf("failed to disable source destination check due to: %v", err)
		} else {
			klog.Infof("disabled source destination check for the instance: %s", instanceID)
		}

		// to prevent EC2 rejecting API call due to API throttling give a delay between the calls
		time.Sleep(awsThrottlingRequestDelay)
	}
}
