package main

import (
	"crypto/tls"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/pagination"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var version string

func main() {
	app := cli.NewApp()

	app.Action = func(c *cli.Context) error {
		log.Printf("[DEBUG] Hello World\n")

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
		networkClient, err := openstack.NewNetworkV2(client, gophercloud.EndpointOpts{
			Region: osRegionName,
		})
		log.Printf("[DEBUG] networkClient: %+v\n", networkClient)

		groups.List(networkClient, groups.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
			securityGroups, err := groups.ExtractGroups(page)
			if err != nil {
				return false, err
			}
			for _, sg := range securityGroups {
				log.Printf("[DEBUG] %s\n", sg.Name)
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
