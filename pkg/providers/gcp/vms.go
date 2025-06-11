package gcp

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/projectdiscovery/cloudlist/pkg/schema"
	"google.golang.org/api/compute/v1"
)

type cloudVMProvider struct {
	id       string
	compute  *compute.Service
	projects []string
}

func (d *cloudVMProvider) name() string {
	return "vms"
}

// GetResource returns all the resources in the store for a provider.
func (d *cloudVMProvider) GetResource(ctx context.Context) (*schema.Resources, error) {
	list := schema.NewResources()
	var wg sync.WaitGroup
	resourcesChan := make(chan *schema.Resource, 100) // Buffer for resources
	errorsChan := make(chan error, len(d.projects))

	// Rate limiter to avoid hitting API limits
	rateLimiter := make(chan struct{}, 5) // Allow 5 concurrent requests

	for _, project := range d.projects {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()

			// Acquire rate limiter token
			rateLimiter <- struct{}{}
			defer func() { <-rateLimiter }()

			instances := d.compute.Instances.AggregatedList(project)
			err := instances.Pages(ctx, func(ial *compute.InstanceAggregatedList) error {
				for zone, instancesScopedList := range ial.Items {
					// Extract zone name from the key (zones/zone-name)
					zoneName := strings.TrimPrefix(zone, "zones/")

					for _, instance := range instancesScopedList.Instances {
						instance := instance

						if len(instance.NetworkInterfaces) == 0 {
							continue
						}
						nic := instance.NetworkInterfaces[0]
						if len(nic.AccessConfigs) == 0 {
							continue
						}
						cfg := nic.AccessConfigs[0]

						// Convert instance labels to tags map
						tags := make(map[string]string)
						for k, v := range instance.Labels {
							tags[k] = v
						}

						// Extract machine type name from URL
						machineType := instance.MachineType
						if idx := strings.LastIndex(machineType, "/"); idx != -1 {
							machineType = machineType[idx+1:]
						}

						resourcesChan <- &schema.Resource{
							ID:         d.id,
							Public:     true,
							Provider:   providerName,
							PublicIPv4: cfg.NatIP,
							PublicIPv6: cfg.ExternalIpv6,
							Service:    d.name(),
							ProjectID:  project,
							Zone:       zoneName,
							Name:       instance.Name,
							Type:       machineType,
							Status:     instance.Status,
							Tags:       tags,
							CreatedAt:  instance.CreationTimestamp,
						}
					}
				}
				return nil
			})
			if err != nil {
				errorsChan <- fmt.Errorf("could not get instances for project %s: %w", project, err)
			}
		}(project)
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

	// Collect all resources
	for resource := range resourcesChan {
		list.Append(resource)
	}

	// Log errors as warnings but continue
	for _, err := range errors {
		log.Printf("Warning: %v\n", err)
	}

	return list, nil
}
