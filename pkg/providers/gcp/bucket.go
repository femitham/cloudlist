package gcp

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/projectdiscovery/cloudlist/pkg/schema"
	"google.golang.org/api/storage/v1"
)

type cloudStorageProvider struct {
	id       string
	storage  *storage.Service
	projects []string
}

func (d *cloudStorageProvider) name() string {
	return "s3"
}

// GetResource returns all the storage resources in the store for a provider.
func (d *cloudStorageProvider) GetResource(ctx context.Context) (*schema.Resources, error) {
	list := schema.NewResources()

	// Build a map from project number to project ID
	projectNumberToID := make(map[string]string)
	for _, p := range d.projects {
		projectNumberToID[p] = p // d.projects is []string of project IDs, so we need to fetch project numbers from API
	}

	for _, project := range d.projects {
		bucketsService := d.storage.Buckets.List(project)
		_ = bucketsService.Pages(context.Background(), func(bal *storage.Buckets) error {
			for _, bucket := range bal.Items {
				projectID := ""
				if bucket.ProjectNumber != 0 {
					projectID = lookupProjectIDByNumber(bucket.ProjectNumber, projectNumberToID)
				}
				resource := &schema.Resource{
					ID:        d.id,
					Provider:  providerName,
					DNSName:   fmt.Sprintf("%s.storage.googleapis.com", bucket.Name),
					Public:    d.isBucketPublic(bucket.Name),
					Service:   d.name(),
					ProjectID: projectID,
				}
				list.Append(resource)
			}
			return nil
		})
	}
	return list, nil
}

// lookupProjectIDByNumber maps a project number to a project ID using the known projects list
func lookupProjectIDByNumber(projectNumber uint64, projectNumberToID map[string]string) string {
	numStr := strconv.FormatUint(projectNumber, 10)
	for id := range projectNumberToID {
		if strings.HasSuffix(id, numStr) { // fallback: try to match by suffix if possible
			return id
		}
	}
	return ""
}

func (d *cloudStorageProvider) getBuckets() ([]*storage.Bucket, error) {
	var buckets []*storage.Bucket
	for _, project := range d.projects {
		bucketsService := d.storage.Buckets.List(project)
		_ = bucketsService.Pages(context.Background(), func(bal *storage.Buckets) error {
			buckets = append(buckets, bal.Items...)
			return nil
		})
	}
	return buckets, nil
}

func (d *cloudStorageProvider) isBucketPublic(bucketName string) bool {
	// Check IAM Policy
	bucketIAMPolicy, err := d.storage.Buckets.GetIamPolicy(bucketName).Do()
	if err == nil {
		for _, binding := range bucketIAMPolicy.Bindings {
			if isStoragePublicRole(binding.Role) {
				for _, member := range binding.Members {
					if member == "allUsers" || member == "allAuthenticatedUsers" {
						return true
					}
				}
			}
		}
	}
	// Optionally, check bucket ACL for public grants (legacy, rare)
	acl, err := d.storage.Buckets.Get(bucketName).Projection("full").Do()
	if err == nil && acl.Acl != nil {
		for _, entry := range acl.Acl {
			if entry.Entity == "allUsers" || entry.Entity == "allAuthenticatedUsers" {
				if entry.Role == "READER" || entry.Role == "OWNER" {
					return true
				}
			}
		}
	}
	return false
}

// isStoragePublicRole returns true if the role is a public storage role
func isStoragePublicRole(role string) bool {
	return strings.HasPrefix(role, "roles/storage.objectViewer") ||
		strings.HasPrefix(role, "roles/storage.legacyBucketReader") ||
		strings.HasPrefix(role, "roles/storage.legacyObjectReader") ||
		strings.HasPrefix(role, "roles/storage.admin") ||
		strings.HasPrefix(role, "roles/storage.legacyBucketOwner") ||
		strings.HasPrefix(role, "roles/storage.legacyObjectOwner") ||
		strings.HasPrefix(role, "roles/storage.objectAdmin") ||
		strings.HasPrefix(role, "roles/storage.objectCreator") ||
		strings.HasPrefix(role, "roles/storage.objectViewer")
}
