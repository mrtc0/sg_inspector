package main

import (
	"fmt"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/nlopes/slack"
	"github.com/takaishi/noguard_sg_checker/config"
	"github.com/takaishi/noguard_sg_checker/openstack"
	"github.com/urfave/cli"
	"regexp"
	"strconv"
	"strings"

	"log"
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
		cli.BoolFlag{
			Name:   "dry-run",
			Usage:  "when this is true, does't post message to slack",
			Hidden: false,
		},
	}

	app.Action = func(c *cli.Context) error {
		return action(c)
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func action(c *cli.Context) error {
	log.SetFlags(log.Lshortfile)
	slack_token := os.Getenv("SLACK_TOKEN")
	slack_channel := os.Getenv("SLACK_CHANNEL_NAME")

	cfg, err := config.ReadConfigFile(c.String("config"))
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

	client, err := openstack.Authenticate(opts, osCert, osKey)
	if err != nil {
		return err
	}

	ps, err := openstack.FetchProjects(client, gophercloud.EndpointOpts{Region: osRegionName})
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

	securityGroups, err := openstack.FetchSecurityGroups(client, gophercloud.EndpointOpts{Region: osRegionName})
	if err != nil {
		return err
	}
	for _, sg := range securityGroups {
		for _, rule := range sg.Rules {
			if rule.RemoteIPPrefix == "0.0.0.0/0" && rule.Protocol == "tcp" {
				ports := []string{}
				if !matchAllowdRule(cfg.Rules, sg, rule) {
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
					if len(params.Attachments) == 20 {
						if !c.Bool("dry-run") {
							err := postMessage(api, slack_channel, params)
							if err != nil {
								return err
							}
						}
						params.Attachments = []slack.Attachment{}
					}
				}
				if len(ports) > 0 {
					fmt.Printf("port = [%s]\n\n", strings.Join(ports, ", "))
				}
			}
		}
	}

	if !c.Bool("dry-run") {
		err = postMessage(api, slack_channel, params)
		if err != nil {
			return err
		}
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
