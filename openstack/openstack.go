package openstack

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/pagination"
	"github.com/nlopes/slack"
	"github.com/open-policy-agent/opa/rego"
	"github.com/pkg/errors"
	"github.com/takaishi/sg_inspector/config"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
)

type OpenStackSecurityGroupChecker struct {
	Cfg         config.Config
	SlackClient *slack.Client
	AuthOptions gophercloud.AuthOptions
	RegionName  string
	Cert        string
	Key         string
	Attachments []slack.Attachment
	Projects    []projects.Project
}

func (checker *OpenStackSecurityGroupChecker) Run() (err error) {
	log.Printf("%+v\n", checker.Cfg.TemporaryAllowdSecurityGroups)

	existNoguardSG := false
	eo := gophercloud.EndpointOpts{Region: checker.RegionName}
	client, err := checker.authenticate(checker.AuthOptions, checker.Cert, checker.Key)
	if err != nil {
		return errors.Wrapf(err, "Failed to authenticate OpenStack API")
	}

	checker.Projects, err = checker.fetchProjects(client, eo)
	if err != nil {
		return errors.Wrapf(err, "Failed to fetch projects")
	}

	for i, rule := range checker.Cfg.Rules {
		for _, p := range checker.Projects {
			if rule.Tenant == p.Name {
				checker.Cfg.Rules[i].TenantID = p.ID
			}
		}
	}

	securityGroups, err := checker.fetchSecurityGroups(client, eo)
	if err != nil {
		return errors.Wrapf(err, "Failed to security groups")
	}

	for _, sg := range securityGroups {
		isFullOpen, err := checker.isFullOpen(sg)
		if err != nil {
			return err
		}
		if isFullOpen {
			existNoguardSG = true
		}
	}

	if existNoguardSG {
		if !checker.Cfg.DryRun {
			err := checker.postWarning(checker.Attachments, "", "")
			if err != nil {
				return errors.Wrapf(err, "Failed to post warning")
			}
		}

		return errors.New("Found no guard security group")

	} else {
		log.Printf("[INFO] 一時的に全解放しているセキュリティグループはありませんでした")
	}

	checker.Attachments = []slack.Attachment{}

	for _, policy := range checker.Cfg.Policies {
		r := rego.New(
			rego.Query("x = data.example.danger[_]"),
			rego.Load([]string{policy.Policy, policy.Data}, nil),
		)

		query, err := r.PrepareForEval(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		existsSGMatchedPolicy := false
		for _, sg := range securityGroups {
			match, err := checker.matchPolicy(query, sg)
			if err != nil {
				return err
			}
			if match {
				existsSGMatchedPolicy = true
			}
		}

		if existsSGMatchedPolicy {
			if !checker.Cfg.DryRun {
				err := checker.postWarning(checker.Attachments, policy.PrefixMessage, policy.SuffixMessage)
				if err != nil {
					return errors.Wrapf(err, "Failed to post warning")
				}
			}

			return errors.New("Found no guard security group")

		} else {
			log.Printf("[INFO] 一時的に全解放しているセキュリティグループはありませんでした")
			return nil
		}
	}
	return nil
}

func contain(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (checker *OpenStackSecurityGroupChecker) postWarning(attachments []slack.Attachment, prefix string, suffix string) error {
	params := slack.PostMessageParameters{
		Username:  checker.Cfg.Username,
		IconEmoji: checker.Cfg.IconEmoji,
	}
	err := postMessage(checker.SlackClient, checker.Cfg.SlackChannel, prefix, params)
	if err != nil {
		return errors.Wrapf(err, "Failed to post message")
	}

	for _, item := range attachments {
		params := slack.PostMessageParameters{
			Username:    checker.Cfg.Username,
			IconEmoji:   checker.Cfg.IconEmoji,
			Attachments: []slack.Attachment{item},
		}
		err = postMessage(checker.SlackClient, checker.Cfg.SlackChannel, "", params)
		if err != nil {
			return errors.Wrapf(err, "Failed to post message")
		}
	}
	err = postMessage(checker.SlackClient, checker.Cfg.SlackChannel, suffix, params)
	if err != nil {
		return errors.Wrapf(err, "Failed to post message")
	}

	return nil
}

func postMessage(api *slack.Client, channel string, text string, params slack.PostMessageParameters) error {
	_, _, err := api.PostMessage(channel, text, params)
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
func (checker *OpenStackSecurityGroupChecker) authenticate(opts gophercloud.AuthOptions, osCert string, osKey string) (*gophercloud.ProviderClient, error) {
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

func (checker *OpenStackSecurityGroupChecker) fetchProjects(client *gophercloud.ProviderClient, eo gophercloud.EndpointOpts) (results []projects.Project, err error) {
	identityClient, err := openstack.NewIdentityV3(client, eo)
	if err != nil {
		return
	}

	projects.List(identityClient, nil).EachPage(func(page pagination.Page) (bool, error) {
		extracted, err := projects.ExtractProjects(page)
		if err != nil {
			return false, err
		}
		for _, project := range extracted {
			results = append(results, project)
		}
		return true, nil
	})
	return
}

func (checker *OpenStackSecurityGroupChecker) fetchSecurityGroups(client *gophercloud.ProviderClient, eo gophercloud.EndpointOpts) (results []groups.SecGroup, err error) {
	networkClient, err := openstack.NewNetworkV2(client, eo)
	if err != nil {
		return
	}

	groups.List(networkClient, groups.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
		securityGroups, err := groups.ExtractGroups(page)
		if err != nil {
			return false, err
		}
		for _, sg := range securityGroups {
			results = append(results, sg)
		}
		return true, nil
	})
	return
}

func (checker *OpenStackSecurityGroupChecker) isFullOpen(sg groups.SecGroup) (bool, error) {
	isFullOpen := false
	for _, rule := range sg.Rules {
		if rule.RemoteIPPrefix == "0.0.0.0/0" && rule.Protocol == "tcp" && rule.Direction == "ingress" {
			if !matchAllowdRule(checker.Cfg.Rules, sg, rule) {
				if contain(checker.Cfg.TemporaryAllowdSecurityGroups, sg.ID) {
					log.Printf("許可済みのSGなのでSlackに警告メッセージは流さない")
					continue
				}
				isFullOpen = true
				projectName, err := getProjectNameFromID(sg.TenantID, checker.Projects)
				if err != nil {
					return isFullOpen, errors.Wrapf(err, "Failed to get project name from id (%s)", sg.TenantID)
				}
				fmt.Printf("[[rules]]\n")
				fmt.Printf("tenant = \"%s\"\n", projectName)
				fmt.Printf("sg = \"%s\"\n", sg.Name)

				fields := []slack.AttachmentField{
					{Title: "Tenant", Value: projectName},
					{Title: "ID", Value: sg.ID},
					{Title: "Name", Value: sg.Name},
					{Title: "PortRange", Value: fmt.Sprintf("%d-%d", rule.PortRangeMin, rule.PortRangeMax)},
				}
				attachment := slack.Attachment{
					Color:  "#ff6347",
					Fields: fields,
				}
				checker.Attachments = append(checker.Attachments, attachment)
			}
		}
	}

	return isFullOpen, nil
}

func (checker *OpenStackSecurityGroupChecker) matchPolicy(query rego.PreparedEvalQuery, sg groups.SecGroup) (bool, error) {
	match := false
	ctx := context.Background()
	var input interface{}
	var s struct {
		groups.SecGroup
		CreatedAt int64 `json:"created_at"`
	}
	s.SecGroup = sg
	s.CreatedAt = sg.CreatedAt.UnixNano()
	jsonData := []byte{}
	jsonData, err := json.Marshal(&s)
	if err != nil {
		return match, err
	}
	err = json.Unmarshal(jsonData, &input)
	if err != nil {
		return match, err
	}

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return match, err
	}
	if len(rs) > 0 {
		match = true
		projectName, err := getProjectNameFromID(sg.TenantID, checker.Projects)
		if err != nil {
			return match, err
		}
		projectName, err = getProjectNameFromID(sg.TenantID, checker.Projects)
		if err != nil {
			return match, err
		}
		fmt.Printf("[[rules]]\n")
		fmt.Printf("tenant = \"%s\"\n", projectName)
		fmt.Printf("sg = \"%s\"\n", sg.Name)
		fmt.Printf("created = \"%s\"\n", sg.CreatedAt.Local())
		fields := []slack.AttachmentField{
			{Title: "Name", Value: sg.Name},
			{Title: "Tenant", Value: projectName, Short: true},
			{Title: "ID", Value: sg.ID, Short: true},
			{Title: "Created", Value: sg.CreatedAt.Local().String()},
		}
		value := ""
		for _, rule := range sg.Rules {
			value += fmt.Sprintf("%s, IP Range: %s, Port Range: %s\n", rule.Direction, rule.RemoteIPPrefix, fmt.Sprintf("%d-%d", rule.PortRangeMin, rule.PortRangeMax))
		}
		fields = append(fields, slack.AttachmentField{
			Title: "Rules",
			Value: value,
		})
		attachment := slack.Attachment{
			Color:  "#ff6347",
			Fields: fields,
		}
		checker.Attachments = append(checker.Attachments, attachment)
		return true, err
	}
	return false, err
}
