package main

import (
	"github.com/gophercloud/gophercloud"
	"github.com/slack-go/slack"
)

func NewOpenStackChecker(conf Config, slackClient *slack.Client) *OpenStackSecurityGroupChecker {
	return &OpenStackSecurityGroupChecker{
		Cfg:         conf,
		SlackClient: slackClient,
		AuthOptions: gophercloud.AuthOptions{
			IdentityEndpoint: conf.OpenStack.AuthURL,
			Username:         conf.OpenStack.Username,
			Password:         conf.OpenStack.Password,
			DomainName:       "Default",
			TenantName:       conf.OpenStack.ProjectName,
		},
		RegionName: conf.OpenStack.RegionName,
		Cert:       conf.OpenStack.Cert,
		Key:        conf.OpenStack.Key,
	}
}
