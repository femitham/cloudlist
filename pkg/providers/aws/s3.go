package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/cloudlist/pkg/schema"
)

// s3Provider is a provider for aws S3 API
type s3Provider struct {
	options ProviderOptions
	s3      *s3.S3
	session *session.Session
}

func (s *s3Provider) name() string {
	return "s3"
}

// GetResource returns all the resources in the store for a provider.
func (s *s3Provider) GetResource(ctx context.Context) (*schema.Resources, error) {
	list := schema.NewResources()
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, s3Client := range s.getS3Clients() {
		wg.Add(1)

		go func(s3Client *s3.S3) {
			defer wg.Done()

			if resources, err := s.getS3Resources(s3Client); err == nil {
				mu.Lock()
				list.Merge(resources)
				mu.Unlock()
			}
		}(s3Client)
	}
	wg.Wait()
	return list, nil
}

func (s *s3Provider) getS3Resources(s3Client *s3.S3) (*schema.Resources, error) {
	list := schema.NewResources()

	// Get account ID from STS
	stsClient := sts.New(s.session)
	identity, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, errors.Wrap(err, "could not get account ID")
	}
	accountID := aws.StringValue(identity.Account)

	req := &s3.ListBucketsInput{}
	listBucketsOutput, err := s3Client.ListBuckets(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not list s3 buckets")
	}

	for _, bucket := range listBucketsOutput.Buckets {
		bucketName := aws.StringValue(bucket.Name)

		// Get bucket location/region
		locInput := &s3.GetBucketLocationInput{
			Bucket: aws.String(bucketName),
		}
		locOutput, err := s3Client.GetBucketLocation(locInput)
		region := "us-east-1" // Default region if not specified
		if err == nil && locOutput.LocationConstraint != nil {
			region = aws.StringValue(locOutput.LocationConstraint)
		}

		// Get bucket tags
		tags := make(map[string]string)
		tagInput := &s3.GetBucketTaggingInput{
			Bucket: aws.String(bucketName),
		}
		if tagOutput, err := s3Client.GetBucketTagging(tagInput); err == nil {
			for _, tag := range tagOutput.TagSet {
				if tag.Key != nil && tag.Value != nil {
					tags[*tag.Key] = *tag.Value
				}
			}
		}

		list.Append(&schema.Resource{
			ID:        s.options.Id,
			Public:    true,
			DNSName:   fmt.Sprintf("%s.s3.amazonaws.com", bucketName),
			Provider:  providerName,
			Service:   s.name(),
			AccountID: accountID,
			Region:    region,
			Tags:      tags,
			Name:      bucketName,
			Type:      "s3-bucket",
			Status:    "Active", // S3 buckets are always active when listed
			CreatedAt: aws.TimeValue(bucket.CreationDate).String(),
		})
	}
	return list, nil
}

func (s *s3Provider) getS3Clients() []*s3.S3 {
	s3Cleints := make([]*s3.S3, 0)
	s3Cleints = append(s3Cleints, s.s3)

	if s.options.AssumeRoleName == "" || len(s.options.AccountIds) < 1 {
		return s3Cleints
	}

	for _, accountId := range s.options.AccountIds {
		roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, s.options.AssumeRoleName)
		creds := stscreds.NewCredentials(s.session, roleARN)

		assumeSession, err := session.NewSession(&aws.Config{
			Region:      aws.String("us-east-1"),
			Credentials: creds,
		})
		if err != nil {
			continue
		}

		s3Cleints = append(s3Cleints, s3.New(assumeSession))
	}
	return s3Cleints
}
