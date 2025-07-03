package gcp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/cloudlist/pkg/schema"
	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	container "google.golang.org/api/container/v1beta1"
	"google.golang.org/api/dns/v1"
	run "google.golang.org/api/run/v1"
	"google.golang.org/api/storage/v1"
)

// Provider is a data provider for gcp API
type Provider struct {
	dns       *dns.Service
	gke       *container.Service
	compute   *compute.Service
	storage   *storage.Service
	functions *cloudfunctions.Service
	run       *run.APIService
	services  schema.ServiceMap
	id        string
	projects  []*cloudresourcemanager.Project
}

var Services = []string{"dns", "gke", "compute", "s3", "cloud-function", "cloud-run"}

const serviceAccountJSON = "gcp_service_account_key"
const providerName = "gcp"

// Name returns the name of the provider
func (p *Provider) Name() string {
	return providerName
}

// ID returns the name of the provider id
func (p *Provider) ID() string {
	return p.id
}

// Services returns the provider services
func (p *Provider) Services() []string {
	return p.services.Keys()
}

// New creates a new provider client for gcp API
func New(options schema.OptionBlock) (*Provider, error) {
	JSONData, ok := options.GetMetadata(serviceAccountJSON)
	if !ok {
		return nil, errorutil.New("could not get API Key")
	}
	id, _ := options.GetMetadata("id")

	provider := &Provider{id: id}
	supportedServicesMap := make(map[string]struct{})
	for _, s := range Services {
		supportedServicesMap[s] = struct{}{}
	}
	services := make(schema.ServiceMap)
	if ss, ok := options.GetMetadata("services"); ok {
		for _, s := range strings.Split(ss, ",") {
			if _, ok := supportedServicesMap[s]; ok {
				services[s] = struct{}{}
			}
		}
	}
	if len(services) == 0 {
		for _, s := range Services {
			services[s] = struct{}{}
		}
	}
	provider.services = services

	creds, err := register(context.Background(), []byte(JSONData))
	if err != nil {
		return nil, FormatGCPError(err)
	}
	if services.Has("dns") {
		dnsService, err := dns.NewService(context.Background(), creds)
		if err != nil {
			return nil, FormatGCPError(err)
		}
		provider.dns = dnsService
	}
	if services.Has("compute") {
		computeService, err := compute.NewService(context.Background(), creds)
		if err != nil {
			return nil, FormatGCPError(err)
		}
		provider.compute = computeService
	}

	if services.Has("gke") {
		containerService, err := container.NewService(context.Background(), creds)
		if err != nil {
			return nil, FormatGCPError(err)
		}
		provider.gke = containerService
	}

	if services.Has("s3") {
		storageService, err := storage.NewService(context.Background(), creds)
		if err != nil {
			return nil, FormatGCPError(err)
		}
		provider.storage = storageService
	}
	if services.Has("cloud-function") {
		functionsService, err := cloudfunctions.NewService(context.Background(), creds)
		if err != nil {
			return nil, FormatGCPError(err)
		}
		provider.functions = functionsService
	}

	if services.Has("cloud-run") {
		cloudRunService, err := run.NewService(context.Background(), creds)
		if err != nil {
			return nil, FormatGCPError(err)
		}
		provider.run = cloudRunService
	}

	projects := []*cloudresourcemanager.Project{}
	manager, err := cloudresourcemanager.NewService(context.Background(), creds)
	if err != nil {
		return nil, FormatGCPError(err)
	}
	list := manager.Projects.List()
	err = list.Pages(context.Background(), func(resp *cloudresourcemanager.ListProjectsResponse) error {
		for _, project := range resp.Projects {
			projects = append(projects, project)
		}
		return nil
	})
	if err != nil {
		return nil, FormatGCPError(err)
	}
	provider.projects = projects
	return provider, nil
}

// Resources returns the provider for an resource deployment source.
func (p *Provider) Resources(ctx context.Context) (*schema.Resources, error) {
	// Create a timeout context
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	finalResources := schema.NewResources()
	var wg sync.WaitGroup
	resourcesChan := make(chan *schema.Resources, 6) // Buffer for all services
	errorsChan := make(chan error, 6)

	// Helper function to fetch resources for a provider
	fetchResources := func(fetch func(context.Context) (*schema.Resources, error)) {
		defer wg.Done()
		resources, err := fetch(ctx)
		if err != nil {
			errorsChan <- err
			return
		}
		if resources != nil {
			resourcesChan <- resources
		}
	}

	// Start a goroutine for each enabled service
	if p.dns != nil {
		wg.Add(1)
		go fetchResources(func(ctx context.Context) (*schema.Resources, error) {
			projectIDs := make([]string, len(p.projects))
			for i, proj := range p.projects {
				projectIDs[i] = proj.ProjectId
			}
			cloudDNSProvider := &cloudDNSProvider{dns: p.dns, id: p.id, projects: projectIDs}
			return cloudDNSProvider.GetResource(ctx)
		})
	}

	if p.gke != nil {
		wg.Add(1)
		go fetchResources(func(ctx context.Context) (*schema.Resources, error) {
			projectIDs := make([]string, len(p.projects))
			for i, proj := range p.projects {
				projectIDs[i] = proj.ProjectId
			}
			GKEProvider := &gkeProvider{svc: p.gke, id: p.id, projects: projectIDs}
			return GKEProvider.GetResource(ctx)
		})
	}

	if p.compute != nil {
		wg.Add(1)
		go fetchResources(func(ctx context.Context) (*schema.Resources, error) {
			projectIDs := make([]string, len(p.projects))
			for i, proj := range p.projects {
				projectIDs[i] = proj.ProjectId
			}
			VMProvider := &cloudVMProvider{compute: p.compute, id: p.id, projects: projectIDs}
			return VMProvider.GetResource(ctx)
		})
	}

	if p.storage != nil {
		wg.Add(1)
		go fetchResources(func(ctx context.Context) (*schema.Resources, error) {
			projectIDs := make([]string, len(p.projects))
			projectNumberToMeta := make(map[string]struct{ID, Name string})
			for i, proj := range p.projects {
				projectIDs[i] = proj.ProjectId
				if proj.ProjectNumber != 0 {
					projectNumberToMeta[fmt.Sprintf("%d", proj.ProjectNumber)] = struct{ID, Name string}{proj.ProjectId, proj.Name}
				}
			}
			storageProvider := &cloudStorageProvider{storage: p.storage, id: p.id, projects: projectIDs, projectNumberToMeta: projectNumberToMeta}
			return storageProvider.GetResource(ctx)
		})
	}

	if p.functions != nil {
		wg.Add(1)
		go fetchResources(func(ctx context.Context) (*schema.Resources, error) {
			projectIDs := make([]string, len(p.projects))
			for i, proj := range p.projects {
				projectIDs[i] = proj.ProjectId
			}
			functionsProvider := &cloudFunctionsProvider{functions: p.functions, id: p.id, projects: projectIDs}
			return functionsProvider.GetResource(ctx)
		})
	}

	if p.run != nil {
		wg.Add(1)
		go fetchResources(func(ctx context.Context) (*schema.Resources, error) {
			projectIDs := make([]string, len(p.projects))
			for i, proj := range p.projects {
				projectIDs[i] = proj.ProjectId
			}
			cloudRunProvider := &cloudRunProvider{run: p.run, id: p.id, projects: projectIDs}
			return cloudRunProvider.GetResource(ctx)
		})
	}

	// Wait for all goroutines to complete in a separate goroutine
	go func() {
		wg.Wait()
		close(resourcesChan)
		close(errorsChan)
	}()

	// Collect errors
	var errors []error
	for err := range errorsChan {
		if err != nil {
			errors = append(errors, err)
		}
	}

	// Merge all resources
	for resources := range resourcesChan {
		if resources != nil {
			finalResources.Merge(resources)
		}
	}

	// If we have any errors, log them as warnings but continue
	for _, err := range errors {
		gologger.Warning().Msgf("Error fetching resources: %s", FormatGCPError(err))
	}

	return finalResources, nil
}

// Verify checks if the GCP provider credentials are valid
func (p *Provider) Verify(ctx context.Context) error {
	if len(p.projects) == 0 {
		return errorutil.New("no accessible GCP projects found with provided credentials")
	}

	// For extra verification, try a minimal API call on one service
	var err error
	for _, project := range p.projects {
		var success bool
		if p.compute != nil {
			if _, err = p.compute.Regions.List(project.ProjectId).Do(); err == nil {
				success = true
			}
		} else if p.dns != nil {
			if _, err = p.dns.ManagedZones.List(project.ProjectId).Do(); err == nil {
				success = true
			}
		} else if p.storage != nil {
			if _, err = p.storage.Buckets.List(project.ProjectId).Do(); err == nil {
				success = true
			}
		} else if p.functions != nil {
			if _, err = p.functions.Projects.Locations.List(project.ProjectId).Do(); err == nil {
				success = true
			}
		} else if p.run != nil {
			if _, err = p.run.Projects.Locations.List(project.ProjectId).Do(); err == nil {
				success = true
			}
		}
		// For any one service to be successful, we can return nil
		if success {
			return nil
		}
	}
	if err != nil {
		return FormatGCPError(err)
	}
	return errorutil.New("no accessible GCP services found with provided credentials")
}
