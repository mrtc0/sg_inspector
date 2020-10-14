package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"

	"github.com/go-redis/redis/v8"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/pagination"
	"github.com/open-policy-agent/opa/rego"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

const REDIS_KEY = "allowed_sg"

type OpenStackSecurityGroupChecker struct {
	Cfg         Config
	SlackClient *slack.Client
	AuthOptions gophercloud.AuthOptions
	RegionName  string
	CACert      string
	Cert        string
	Key         string
	Attachments []slack.Attachment
	Projects    []projects.Project
}

func (checker *OpenStackSecurityGroupChecker) Run() (err error) {
	redisClient := redis.NewClient(
		&redis.Options{
			Addr:     "localhost:6379",
			Password: "",
			DB:       0,
		})
	len, err := redisClient.LLen(context.Background(), REDIS_KEY).Result()
	if err != nil {
		return err
	}
	allowed_sg, err := redisClient.LRange(context.Background(), REDIS_KEY, 0, len).Result()
	if err != nil {
		return err
	}
	logrus.Infof("Temporary allowed security groups: %+v\n", allowed_sg)

	existNoguardSG := false
	eo := gophercloud.EndpointOpts{Region: checker.RegionName}
	client, err := checker.authenticate(checker.AuthOptions, checker.CACert, checker.Cert, checker.Key)
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

	logrus.Info("Start to find security group is allowed to access from any.")

	for _, sg := range securityGroups {
		isFullOpen, err := checker.isFullOpen(sg, allowed_sg)
		if err != nil {
			return err
		}
		if isFullOpen {
			existNoguardSG = true
		}
	}

	if existNoguardSG {
		if !checker.Cfg.DryRun {
			err := checker.postWarning(checker.Attachments, checker.Cfg.PrefixMessage, checker.Cfg.SuffixMessage)
			if err != nil {
				return errors.Wrapf(err, "Failed to post warning")
			}
		}

		logrus.Info("Security group that allowed to access from any is found.")

	} else {
		logrus.Info("No security group that allowed to access from any is found.")
	}

	checker.Attachments = []slack.Attachment{}

	logrus.Info("Start to find security group don't match policy.")

	for _, policy := range checker.Cfg.Policies {
		paths := []string{}
		if policy.Policy != "" {
			paths = append(paths, policy.Policy)
		}
		if policy.Data != "" {
			paths = append(paths, policy.Data)
		}
		r := rego.New(
			rego.Query("x = data.example.allow"),
			rego.Load(paths, nil),
		)

		query, err := r.PrepareForEval(context.Background())
		if err != nil {
			return err
		}
		existsSGMatchedPolicy := false
		for _, sg := range securityGroups {
			if contain(allowed_sg, sg.ID) {
				logrus.Info("許可済みのSGなのでSlackに警告メッセージは流さない")
				continue
			}
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
			logrus.Info("Security group that match policy is found.")
		} else {
			logrus.Info("No security group that match policy is found.")
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
	err := postMessage(checker.SlackClient, checker.Cfg.SlackChannel, prefix, nil, params)
	if err != nil {
		return errors.Wrapf(err, "Failed to post prefix message")
	}

	for _, item := range attachments {
		params := slack.PostMessageParameters{
			Username:  checker.Cfg.Username,
			IconEmoji: checker.Cfg.IconEmoji,
		}
		attachments := []slack.Attachment{
			item,
		}
		err = postMessage(checker.SlackClient, checker.Cfg.SlackChannel, "", attachments, params)
		if err != nil {
			return errors.Wrapf(err, "Failed to post attachments")
		}
	}
	err = postMessage(checker.SlackClient, checker.Cfg.SlackChannel, suffix, nil, params)
	if err != nil {
		return errors.Wrapf(err, "Failed to post suffix message")
	}

	return nil
}

func postMessage(api *slack.Client, channel string, text string, attachments []slack.Attachment, params slack.PostMessageParameters) error {
	_, _, err := api.PostMessage(channel, slack.MsgOptionText(text, false), slack.MsgOptionAttachments(attachments...), slack.MsgOptionPostMessageParameters(params))
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

func matchAllowdRule(allowdRules []Rule, sg groups.SecGroup, rule rules.SecGroupRule) bool {
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
func (checker *OpenStackSecurityGroupChecker) authenticate(opts gophercloud.AuthOptions, caCert string, osCert string, osKey string) (*gophercloud.ProviderClient, error) {
	client, err := openstack.NewClient(opts.IdentityEndpoint)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{}

	if caCert != "" {
		CA_Pool := x509.NewCertPool()

		severCert, err := ioutil.ReadFile(caCert)
		if err != nil {
			return nil, err
		}
		CA_Pool.AppendCertsFromPEM(severCert)

		tlsConfig.RootCAs = CA_Pool
	}

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
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig}

	client.HTTPClient.Transport = transport

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

func (checker *OpenStackSecurityGroupChecker) isFullOpen(sg groups.SecGroup, allowed_sg []string) (bool, error) {
	isFullOpen := false
	for _, rule := range sg.Rules {
		if rule.RemoteIPPrefix == "0.0.0.0/0" && rule.Protocol == "tcp" && rule.Direction == "ingress" {
			if !matchAllowdRule(checker.Cfg.Rules, sg, rule) {
				if contain(allowed_sg, sg.ID) {
					logrus.Info("許可済みのSGなのでSlackに警告メッセージは流さない")
					continue
				}
				isFullOpen = true
				projectName, err := getProjectNameFromID(sg.TenantID, checker.Projects)
				if err != nil {
					projectName = sg.TenantID
					//return isFullOpen, errors.Wrapf(err, "Failed to get project name from id (%s)", sg.TenantID)
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
	if len(rs) > 0 && rs[0].Bindings["x"].(bool) {
		match = true
		projectName, err := getProjectNameFromID(sg.TenantID, checker.Projects)
		if err != nil {
			err = nil
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
