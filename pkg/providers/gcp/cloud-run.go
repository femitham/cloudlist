package gcp

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/projectdiscovery/cloudlist/pkg/schema"
	run "google.golang.org/api/run/v1"
)

type cloudRunProvider struct {
	id       string
	run      *run.APIService
	projects []string
}

func (d *cloudRunProvider) name() string {
	return "cloud-run"
}

// GetResource returns all the Cloud Run resources in the store for a provider.
func (d *cloudRunProvider) GetResource(ctx context.Context) (*schema.Resources, error) {
	list := schema.NewResources()
	services, err := d.getServices()
	if err != nil {
		return nil, FormatGCPError(err)
	}

	for _, svc := range services {
		service := svc.service
		projectID := svc.projectID
		serviceUrl, _ := url.Parse(service.Status.Url)

		// Extract location from service name
		// Format: projects/{project}/locations/{location}/services/{service}
		parts := strings.Split(service.Metadata.Name, "/")
		location := ""
		if len(parts) >= 4 {
			location = parts[3]
		}

		// Extract labels/tags
		tags := make(map[string]string)
		for k, v := range service.Metadata.Labels {
			tags[k] = v
		}

		resource := &schema.Resource{
			ID:        d.id,
			Provider:  providerName,
			DNSName:   serviceUrl.Hostname(),
			Public:    d.isPublicService(service.Metadata.SelfLink),
			Service:   d.name(),
			ProjectID: projectID,
			Region:    location,
			Name:      service.Metadata.Name,
			Tags:      tags,
		}
		list.Append(resource)
	}
	return list, nil
}

type projectService struct {
	projectID string
	service   *run.Service
}

func (d *cloudRunProvider) getServices() ([]projectService, error) {
	var services []projectService
	for _, project := range d.projects {
		locationsService := d.run.Projects.Locations.List(fmt.Sprintf("projects/%s", project))
		locationsResponse, err := locationsService.Do()
		if err != nil {
			continue
		}

		for _, location := range locationsResponse.Locations {
			servicesService := d.run.Projects.Locations.Services.List(location.Name)
			servicesResponse, err := servicesService.Do()
			if err != nil {
				continue
			}
			for _, svc := range servicesResponse.Items {
				services = append(services, projectService{projectID: project, service: svc})
			}
		}
	}
	return services, nil
}

func (d *cloudRunProvider) isPublicService(serviceName string) bool {
	serviceIAMPolicy, err := d.run.Projects.Locations.Services.GetIamPolicy(serviceName).Do()
	if err == nil {
		for _, binding := range serviceIAMPolicy.Bindings {
			if binding.Role == "roles/run.invoker" {
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
