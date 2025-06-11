package gcp

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/projectdiscovery/cloudlist/pkg/schema"
	"google.golang.org/api/cloudfunctions/v1"
)

type cloudFunctionsProvider struct {
	id        string
	functions *cloudfunctions.Service
	projects  []string
}

func (d *cloudFunctionsProvider) name() string {
	return "cloud-function"
}

// GetResource returns all the Cloud Function resources in the store for a provider.
func (d *cloudFunctionsProvider) GetResource(ctx context.Context) (*schema.Resources, error) {
	list := schema.NewResources()
	functions, err := d.getFunctions()
	if err != nil {
		return nil, fmt.Errorf("could not get functions: %s", err)
	}
	for _, function := range functions {
		if function == nil || function.HttpsTrigger == nil {
			continue
		}
		funcUrl, err := url.Parse(function.HttpsTrigger.Url)
		if err != nil {
			continue
		}

		// Extract region from function name
		// Format: projects/{project}/locations/{location}/functions/{function}
		parts := strings.Split(function.Name, "/")
		var region string
		if len(parts) >= 4 {
			region = parts[3]
		}

		// Get project ID from the parent project
		projectID := ""
		for _, project := range d.projects {
			if strings.HasPrefix(function.Name, fmt.Sprintf("projects/%s/", project)) {
				projectID = project
				break
			}
		}

		// Convert function labels to tags
		tags := make(map[string]string)
		for k, v := range function.Labels {
			tags[k] = v
		}

		resource := &schema.Resource{
			ID:        d.id,
			Provider:  providerName,
			DNSName:   funcUrl.Hostname(),
			Public:    d.isPublicFunction(function.Name),
			Service:   d.name(),
			ProjectID: projectID,
			Region:    region,
			Name:      function.Name[strings.LastIndex(function.Name, "/")+1:],
			Type:      function.Runtime,
			Status:    function.Status,
			Tags:      tags,
			CreatedAt: function.UpdateTime, // Cloud Functions API doesn't expose creation time
		}
		list.Append(resource)
	}
	return list, nil
}

func (d *cloudFunctionsProvider) getFunctions() ([]*cloudfunctions.CloudFunction, error) {
	var functions []*cloudfunctions.CloudFunction
	for _, project := range d.projects {
		functionsService := d.functions.Projects.Locations.Functions.List(fmt.Sprintf("projects/%s/locations/-", project))
		_ = functionsService.Pages(context.Background(), func(fal *cloudfunctions.ListFunctionsResponse) error {
			functions = append(functions, fal.Functions...)
			return nil
		})
	}
	return functions, nil
}

func (d *cloudFunctionsProvider) isPublicFunction(functionName string) bool {
	functionIAMPolicy, err := d.functions.Projects.Locations.Functions.GetIamPolicy(functionName).Do()
	if err == nil {
		for _, binding := range functionIAMPolicy.Bindings {
			if binding.Role == "roles/cloudfunctions.invoker" {
				for _, member := range binding.Members {
					if member == "allUsers" || member == "allAuthenticatedUsers" {
						return true
					}
				}
			}
		}
	}
	return false
}
