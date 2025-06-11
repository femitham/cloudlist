package aws

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/cloudlist/pkg/schema"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

// eksProvider is a provider for AWS EKS API.
type eksProvider struct {
	options   ProviderOptions
	eksClient *eks.EKS
	session   *session.Session
	regions   *ec2.DescribeRegionsOutput
}

func (ep *eksProvider) name() string {
	return "eks"
}

// GetResource returns all the resources in the store for a provider.
func (ep *eksProvider) GetResource(ctx context.Context) (*schema.Resources, error) {
	list := schema.NewResources()
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, region := range ep.regions.Regions {
		for _, eksClient := range ep.getEksClients(region.RegionName) {
			wg.Add(1)

			go func(client *eks.EKS) {
				defer wg.Done()
				if resources, err := ep.listEKSResources(client); err == nil {
					mu.Lock()
					list.Merge(resources)
					mu.Unlock()
				}
			}(eksClient)
		}
	}
	wg.Wait()
	return list, nil
}

func (ep *eksProvider) listEKSResources(eksClient *eks.EKS) (*schema.Resources, error) {
	list := schema.NewResources()

	// Get account ID from STS
	stsClient := sts.New(ep.session)
	identity, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, errors.Wrap(err, "could not get account ID")
	}
	accountID := aws.StringValue(identity.Account)

	// Get current region from session
	region := *eksClient.Config.Region

	req := &eks.ListClustersInput{}
	for {
		clustersOutput, err := eksClient.ListClusters(req)
		if err != nil {
			return nil, errors.Wrap(err, "could not list EKS clusters")
		}

		for _, clusterName := range clustersOutput.Clusters {
			// Get cluster details
			cluster, err := eksClient.DescribeCluster(&eks.DescribeClusterInput{
				Name: clusterName,
			})
			if err != nil {
				continue
			}

			// Convert cluster tags to map
			tags := make(map[string]string)
			for k, v := range cluster.Cluster.Tags {
				if v != nil {
					tags[k] = *v
				}
			}

			// Get cluster nodes
			clientset, err := newClientset(cluster.Cluster)
			if err != nil {
				continue
			}

			nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				continue
			}

			for _, node := range nodes.Items {
				var podIPs []string
				// List IP addresses of pods running on the node
				pods, err := clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
					FieldSelector: fmt.Sprintf("spec.nodeName=%s", node.GetName()),
				})
				if err != nil {
					continue
				}
				// Collect pod IP addresses
				for _, pod := range pods.Items {
					for _, podIP := range pod.Status.PodIPs {
						podIPs = append(podIPs, podIP.IP)
					}
				}
				// Node IP
				nodeIP := node.Status.Addresses[0].Address
				list.Append(&schema.Resource{
					Provider:   providerName,
					ID:         node.GetName(),
					PublicIPv4: nodeIP,
					Public:     true,
					Service:    ep.name(),
					AccountID:  accountID,
					Region:     region,
					Tags:       tags,
					Name:       aws.StringValue(cluster.Cluster.Name),
					Type:       aws.StringValue(cluster.Cluster.Version),
					Status:     aws.StringValue(cluster.Cluster.Status),
					CreatedAt:  aws.TimeValue(cluster.Cluster.CreatedAt).String(),
				})
				// Pod IPs
				for _, podIP := range podIPs {
					list.Append(&schema.Resource{
						Provider:    providerName,
						ID:          node.GetName(),
						PrivateIpv4: podIP,
						Public:      false,
						Service:     ep.name(),
						AccountID:   accountID,
						Region:      region,
						Tags:        tags,
						Name:        aws.StringValue(cluster.Cluster.Name),
						Type:        aws.StringValue(cluster.Cluster.Version),
						Status:      aws.StringValue(cluster.Cluster.Status),
						CreatedAt:   aws.TimeValue(cluster.Cluster.CreatedAt).String(),
					})
				}
			}
		}
		if aws.StringValue(clustersOutput.NextToken) == "" {
			break
		}
		req.SetNextToken(*clustersOutput.NextToken)
	}
	return list, nil
}

func (ep *eksProvider) getEksClients(region *string) []*eks.EKS {
	eksClients := make([]*eks.EKS, 0)

	eksClient := eks.New(
		ep.session,
		aws.NewConfig().WithRegion(aws.StringValue(region)),
	)
	eksClients = append(eksClients, eksClient)

	if ep.options.AssumeRoleName == "" || len(ep.options.AccountIds) < 1 {
		return eksClients
	}

	for _, accountId := range ep.options.AccountIds {
		roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, ep.options.AssumeRoleName)
		creds := stscreds.NewCredentials(ep.session, roleARN)

		assumeSession, err := session.NewSession(&aws.Config{
			Region:      region,
			Credentials: creds,
		})
		if err != nil {
			continue
		}

		eksClients = append(eksClients, eks.New(assumeSession))
	}
	return eksClients
}

func newClientset(cluster *eks.Cluster) (*kubernetes.Clientset, error) {
	gen, err := token.NewGenerator(true, false)
	if err != nil {
		return nil, err
	}
	opts := &token.GetTokenOptions{
		ClusterID: aws.StringValue(cluster.Name),
	}
	tok, err := gen.GetWithOptions(opts)
	if err != nil {
		return nil, err
	}
	ca, err := base64.StdEncoding.DecodeString(aws.StringValue(cluster.CertificateAuthority.Data))
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(
		&rest.Config{
			Host:        aws.StringValue(cluster.Endpoint),
			BearerToken: tok.Token,
			TLSClientConfig: rest.TLSClientConfig{
				CAData: ca,
			},
		},
	)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}
