package main

import (
	"crypto/tls"
	"github.com/BurntSushi/toml"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v2/tenants"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/pagination"
	"github.com/takaishi/noguard_sg_checker/config"
	"github.com/urfave/cli"
	"strconv"

	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var version string

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config, c",
			Value: "config.yaml",
		},
	}

	app.Action = func(c *cli.Context) error {
		var cfg config.Config
		_, err := toml.DecodeFile(c.String("config"), &cfg)

		osAuthUrl := os.Getenv("OS_AUTH_URL")
		osUsername := os.Getenv("OS_USERNAME")
		osPassword := os.Getenv("OS_PASSWORD")
		osRegionName := os.Getenv("OS_REGION_NAME")
		osTenantName := os.Getenv("OS_TENANT_NAME")
		osCert := os.Getenv("OS_CERT")
		osKey := os.Getenv("OS_KEY")

		opts := gophercloud.AuthOptions{
			IdentityEndpoint: osAuthUrl,
			Username:         osUsername,
			Password:         osPassword,
			DomainName:       "Default",
			TenantName:       osTenantName,
		}

		client, err := openstack.NewClient(osAuthUrl)
		if err != nil {
			return err
		}
		tlsConfig := &tls.Config{}
		if osCert != "" && osKey != "" {
			clientCert, err := ioutil.ReadFile(osCert)
			if err != nil {
				return err
			}
			clientKey, err := ioutil.ReadFile(osKey)
			if err != nil {
				return err
			}
			cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
			if err != nil {
				return err
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
			tlsConfig.BuildNameToCertificate()
			transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig}

			client.HTTPClient.Transport = transport
		}

		err = openstack.Authenticate(client, opts)
		if err != nil {
			return err
		}

		identityClient, err := openstack.NewIdentityV2(client, gophercloud.EndpointOpts{
			Region: osRegionName})
		if err != nil {
			return err
		}
		ts := []tenants.Tenant{}
		tenants.List(identityClient, nil).EachPage(func(page pagination.Page) (bool, error) {
			extracted, err := tenants.ExtractTenants(page)
			if err != nil {
				return false, err
			}
			for _, tenant := range extracted {
				ts = append(ts, tenant)
			}

			return true, nil
		})

		networkClient, err := openstack.NewNetworkV2(client, gophercloud.EndpointOpts{
			Region: osRegionName,
		})
		if err != nil {
			return err
		}

		groups.List(networkClient, groups.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
			securityGroups, err := groups.ExtractGroups(page)
			if err != nil {
				return false, err
			}
			for _, sg := range securityGroups {
				for _, rule := range sg.Rules {
					if rule.RemoteIPPrefix == "0.0.0.0/0" && rule.Protocol == "tcp" {
						var tenantName string
						for _, t := range ts {
							if t.ID == sg.TenantID {
								tenantName = t.Name
							}
						}
						for _, allowdRule := range cfg.Rules {
							if allowdRule.Tenant == tenantName && allowdRule.SG == sg.Name && contains(allowdRule.Port, strconv.Itoa(rule.PortRangeMin)) {
								log.Printf("[DEBUG] %s %s: %d-%d\n", tenantName, sg.Name, rule.PortRangeMin, rule.PortRangeMax)

							} else {

							}
						}
					}
				}
			}

			return true, nil
		})

		return nil
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}
