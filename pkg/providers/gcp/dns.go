package gcp

import (
	"context"
	"fmt"
	"log"

	"github.com/projectdiscovery/cloudlist/pkg/schema"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/dns/v1"
)

// cloudDNSProvider is a provider for aws Route53 API
type cloudDNSProvider struct {
	id       string
	dns      *dns.Service
	projects []*cloudresourcemanager.Project
}

func (d *cloudDNSProvider) name() string {
	return "dns"
}

// GetResource returns all the resources in the store for a provider.
func (d *cloudDNSProvider) GetResource(ctx context.Context) (*schema.Resources, error) {
	list := schema.NewResources()

	for _, project := range d.projects {
		zone := d.dns.ManagedZones.List(project.ProjectId)
		err := zone.Pages(context.Background(), func(resp *dns.ManagedZonesListResponse) error {
			for _, z := range resp.ManagedZones {
				resources := d.dns.ResourceRecordSets.List(project.ProjectId, z.Name)
				err := resources.Pages(context.Background(), func(r *dns.ResourceRecordSetsListResponse) error {
					items := d.parseRecordsForResourceSet(r, project, z)
					list.Merge(items)
					return nil
				})
				if err != nil {
					log.Printf("Could not get resource_records for zone %s in project %s: %s\n", z.Name, project.ProjectId, err)
					continue
				}
			}
			return nil
		})
		if err != nil {
			log.Printf("Could not get all zones for project %s: %s\n", project.ProjectId, err)
			continue
		}
	}
	return list, nil
}

// parseRecordsForResourceSet parses and returns the records for a resource set
func (d *cloudDNSProvider) parseRecordsForResourceSet(r *dns.ResourceRecordSetsListResponse, project *cloudresourcemanager.Project, zone *dns.ManagedZone) *schema.Resources {
	list := schema.NewResources()

	for _, resource := range r.Rrsets {
		if resource.Type != "A" && resource.Type != "CNAME" && resource.Type != "AAAA" {
			continue
		}

		for _, data := range resource.Rrdatas {
			// Extract tags from zone labels
			tags := make(map[string]string)
			for k, v := range zone.Labels {
				tags[k] = v
			}
			// Add project metadata as tags
			tags["project_name"] = project.Name
			tags["project_number"] = fmt.Sprintf("%d", project.ProjectNumber)
			tags["lifecycle_state"] = project.LifecycleState

			baseResource := &schema.Resource{
				Public:    true,
				ID:        d.id,
				Provider:  providerName,
				Service:   d.name(),
				ProjectID: project.ProjectId,
				Name:      zone.Name,
				Type:      "dns." + resource.Type,
				Status:    "ACTIVE",
				Region:    zone.DnsName,
				Tags:      tags,
			}

			// Set the appropriate field based on record type
			if resource.Type == "A" {
				baseResource.PublicIPv4 = data
				baseResource.DNSName = resource.Name
			} else if resource.Type == "AAAA" {
				baseResource.PublicIPv6 = data
				baseResource.DNSName = resource.Name
			} else if resource.Type == "CNAME" {
				baseResource.DNSName = data
			}

			list.Items = append(list.Items, baseResource)
		}
	}
	return list
}
