package main

import (
	"crypto/tls"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/pagination"
	"github.com/joho/godotenv"
	"github.com/nlopes/slack"
	"github.com/takaishi/noguard_sg_checker/config"
	"github.com/urfave/cli"
	"regexp"
	"strconv"

	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var version string

func Authenticate(opts gophercloud.AuthOptions, osCert string, osKey string) (*gophercloud.ProviderClient, error) {
	client, err := openstack.NewClient(opts.IdentityEndpoint)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{}
	if osCert != "" && osKey != "" {
		clientCert, err := ioutil.ReadFile(osCert)
		if err != nil {
			return nil, err
		}
		clientKey, err := ioutil.ReadFile(osKey)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.BuildNameToCertificate()
		transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig}

		client.HTTPClient.Transport = transport
	}

	err = openstack.Authenticate(client, opts)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func fetchProjects(client *gophercloud.ProviderClient, eo gophercloud.EndpointOpts) ([]projects.Project, error) {
	ps := []projects.Project{}
	identityClient, err := openstack.NewIdentityV3(client, eo)
	if err != nil {
		return nil, err
	}
	projects.List(identityClient, nil).EachPage(func(page pagination.Page) (bool, error) {
		extracted, err := projects.ExtractProjects(page)
		if err != nil {
			return false, err
		}
		for _, project := range extracted {
			ps = append(ps, project)
		}

		return true, nil
	})

	return ps, nil
}

func fetchSecurityGroups(client *gophercloud.ProviderClient, eo gophercloud.EndpointOpts) ([]groups.SecGroup, error) {
	sgs := []groups.SecGroup{}

	networkClient, err := openstack.NewNetworkV2(client, eo)
	if err != nil {
		return nil, err
	}

	groups.List(networkClient, groups.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
		securityGroups, err := groups.ExtractGroups(page)
		if err != nil {
			return false, err
		}
		for _, sg := range securityGroups {
			sgs = append(sgs, sg)
		}
		return true, nil
	})
	return sgs, nil
}

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config, c",
			Value: "config.yaml",
		},
	}

	app.Action = func(c *cli.Context) error {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}
		slack_token := os.Getenv("SLACK_TOKEN")
		slack_channel := os.Getenv("SLACK_CHANNEL_NAME")

		var cfg config.Config
		_, err = toml.DecodeFile(c.String("config"), &cfg)
		if err != nil {
			return err
		}
		api := slack.New(slack_token)
		params := slack.PostMessageParameters{
			Username:  cfg.Username,
			IconEmoji: cfg.IconEmoji,
		}

		osAuthUrl := os.Getenv("OS_AUTH_URL")
		osUsername := os.Getenv("OS_USERNAME")
		osPassword := os.Getenv("OS_PASSWORD")
		osRegionName := os.Getenv("OS_REGION_NAME")
		osProjectName := os.Getenv("OS_PROJECT_NAME")
		osCert := os.Getenv("OS_CERT")
		osKey := os.Getenv("OS_KEY")

		opts := gophercloud.AuthOptions{
			IdentityEndpoint: osAuthUrl,
			Username:         osUsername,
			Password:         osPassword,
			DomainName:       "Default",
			TenantName:       osProjectName,
		}

		client, err := Authenticate(opts, osCert, osKey)
		if err != nil {
			return err
		}

		ps, err := fetchProjects(client, gophercloud.EndpointOpts{Region: osRegionName})
		if err != nil {
			return err
		}

		for i, rule := range cfg.Rules {
			for _, p := range ps {
				if rule.Tenant == p.Name {
					cfg.Rules[i].TenantID = p.ID
				}
			}
		}

		securityGroups, err := fetchSecurityGroups(client, gophercloud.EndpointOpts{Region: osRegionName})
		if err != nil {
			return err
		}
		for _, sg := range securityGroups {
			for _, rule := range sg.Rules {
				if rule.RemoteIPPrefix == "0.0.0.0/0" && rule.Protocol == "tcp" {
					if !matchAllowdRule(cfg.Rules, sg, rule) {
						projectName, err := getProjectNameFromID(sg.TenantID, ps)
						if err != nil {
							return err
						}
						log.Printf("[DEBUG] %s %s: %d-%d\n", projectName, sg.Name, rule.PortRangeMin, rule.PortRangeMax)
						attachment := slack.Attachment{
							Title: fmt.Sprintf("テナント: %s", projectName),
							Text:  fmt.Sprintf("SecurityGroup: %s\nPortRange: %d-%d", sg.Name, rule.PortRangeMin, rule.PortRangeMax),
							Color: "#ff6347",
						}
						params.Attachments = append(params.Attachments, attachment)
						if len(params.Attachments) == 20 {
							err := postMessage(api, slack_channel, params)
							if err != nil {
								return err
							}
							params.Attachments = []slack.Attachment{}
						}
					}
				}
			}
		}

		err = postMessage(api, slack_channel, params)
		if err != nil {
			return err
		}

		return nil
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func postMessage(api *slack.Client, channel string, params slack.PostMessageParameters) error {
	_, _, err := api.PostMessage(channel, "全解放しているセキュリティグループがあるように見えるぞ！大丈夫？？？", params)
	if err != nil {
		return err
	}
	return nil
}

func getProjectNameFromID(id string, ps []projects.Project) (string, error) {
	for _, p := range ps {
		if p.ID == id {
			return p.Name, nil
		}
	}
	return "", fmt.Errorf("Not found project: %s", id)
}

func matchAllowdRule(allowdRules []config.Rule, sg groups.SecGroup, rule rules.SecGroupRule) bool {
	for _, allowdRule := range allowdRules {
		if allowdRule.TenantID == rule.TenantID && allowdRule.SG == sg.Name {
			r := regexp.MustCompile(`(\d*)-(\d*)`)
			for _, port := range allowdRule.Port {
				if r.MatchString(port) {
					result := r.FindAllStringSubmatch(port, -1)
					if result[0][1] == strconv.Itoa(rule.PortRangeMin) && result[0][2] == strconv.Itoa(rule.PortRangeMax) {
						return true
					}
				}
			}
			if contains(allowdRule.Port, strconv.Itoa(rule.PortRangeMin)) {
				return true
			}
		}
	}
	return false
}

func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}
