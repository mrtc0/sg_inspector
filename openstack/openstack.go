package openstack

import (
	"crypto/tls"
	"fmt"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/pagination"
	"github.com/nlopes/slack"
	"github.com/takaishi/noguard_sg_checker/config"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"github.com/robfig/cron"
)

type OpenStackSecurityGroupChecker struct {
	Cfg         config.Config
	SlackClient *slack.Client
	AuthOptions gophercloud.AuthOptions
	RegionName  string
	Cert        string
	Key         string
}

func (checker *OpenStackSecurityGroupChecker) Start() error {
	server := cron.New()
	server.AddFunc(checker.Cfg.CheckInterval, func() { checker.CheckSecurityGroups() })
	server.Run()

	return nil
}

func (checker *OpenStackSecurityGroupChecker) CheckSecurityGroups() error {
	eo := gophercloud.EndpointOpts{Region: checker.RegionName}
	params := slack.PostMessageParameters{
		Username:  checker.Cfg.Username,
		IconEmoji: checker.Cfg.IconEmoji,
	}
	client, err := checker.Authenticate(checker.AuthOptions, checker.Cert, checker.Key)
	if err != nil {
		return err
	}

	ps, err := checker.FetchProjects(client, eo)
	if err != nil {
		return err
	}

	for i, rule := range checker.Cfg.Rules {
		for _, p := range ps {
			if rule.Tenant == p.Name {
				checker.Cfg.Rules[i].TenantID = p.ID
			}
		}
	}

	securityGroups, err := checker.FetchSecurityGroups(client, eo)
	if err != nil {
		return err
	}
	for _, sg := range securityGroups {
		for _, rule := range sg.Rules {
			if rule.RemoteIPPrefix == "0.0.0.0/0" && rule.Protocol == "tcp"  && rule.Direction == "ingress"{
				ports := []string{}
				if !matchAllowdRule(checker.Cfg.Rules, sg, rule) {
					projectName, err := getProjectNameFromID(sg.TenantID, ps)
					if err != nil {
						return err
					}
					fmt.Printf("[[rules]]\n")
					fmt.Printf("tenant = \"%s\"\n", projectName)
					fmt.Printf("sg = \"%s\"\n", sg.Name)
					if rule.PortRangeMin == rule.PortRangeMax {
						ports = append(ports, fmt.Sprintf("\"%d\"", rule.PortRangeMin))
					} else {
						ports = append(ports, fmt.Sprintf("\"%d-%d\"", rule.PortRangeMin, rule.PortRangeMax))
					}

					attachment := slack.Attachment{
						Title: fmt.Sprintf("テナント: %s", projectName),
						Text:  fmt.Sprintf("SecurityGroup: %s\nPortRange: %d-%d", sg.Name, rule.PortRangeMin, rule.PortRangeMax),
						Color: "#ff6347",
					}
					params.Attachments = append(params.Attachments, attachment)
					if !checker.Cfg.DryRun && len(params.Attachments) == 20 {
						err := postMessage(checker.SlackClient, checker.Cfg.SlackChannel, params)
						if err != nil {
							return err
						}
						params.Attachments = []slack.Attachment{}
					}
				}
				if len(params.Attachments) > 0 {
					fmt.Printf("port = [%s]\n\n", strings.Join(ports, ", "))
				}
			}
		}
	}

	if !checker.Cfg.DryRun && len(params.Attachments) > 0 {
		err = postMessage(checker.SlackClient, checker.Cfg.SlackChannel, params)
		if err != nil {
			return err
		}
	} else {
		log.Printf("[INFO] 一時的に全解放しているセキュリティグループはありませんでした")
	}

	return nil
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
		if allowdRule.TenantID == sg.TenantID && allowdRule.SG == sg.Name {
			r := regexp.MustCompile(`(\d*)-(\d*)`)
			for _, port := range allowdRule.Port {
				if r.MatchString(port) {
					result := r.FindAllStringSubmatch(port, -1)
					if result[0][1] == strconv.Itoa(rule.PortRangeMin) && result[0][2] == strconv.Itoa(rule.PortRangeMax) {
						return true
					}
				}
			}
			if contains(allowdRule.Port, strconv.Itoa(rule.PortRangeMin)) && contains(allowdRule.Port, strconv.Itoa(rule.PortRangeMax)) {
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
func (checker *OpenStackSecurityGroupChecker) Authenticate(opts gophercloud.AuthOptions, osCert string, osKey string) (*gophercloud.ProviderClient, error) {
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

func (checker *OpenStackSecurityGroupChecker) FetchProjects(client *gophercloud.ProviderClient, eo gophercloud.EndpointOpts) ([]projects.Project, error) {
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

func (checker *OpenStackSecurityGroupChecker) FetchSecurityGroups(client *gophercloud.ProviderClient, eo gophercloud.EndpointOpts) ([]groups.SecGroup, error) {
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
