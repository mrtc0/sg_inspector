package main

import (
	"github.com/gophercloud/gophercloud"
	"github.com/pkg/errors"
	"github.com/slack-go/slack"
	"github.com/urfave/cli"
)

func StartCheck(c *cli.Context) error {
	cfg, err := ReadConfig(c.String("config"), c.Bool("dry-run"))
	if err != nil {
		return err
	}

	api := slack.New(cfg.SlackToken)

	checker := OpenStackSecurityGroupChecker{
		Cfg:         cfg,
		SlackClient: api,
		AuthOptions: gophercloud.AuthOptions{
			IdentityEndpoint: cfg.OpenStack.AuthURL,
			Username:         cfg.OpenStack.Username,
			Password:         cfg.OpenStack.Password,
			DomainName:       "Default",
			TenantName:       cfg.OpenStack.ProjectName,
		},
		RegionName: cfg.OpenStack.RegionName,
		Cert:       cfg.OpenStack.Cert,
		Key:        cfg.OpenStack.Key,
	}

	err = checker.Run()
	if err != nil {
		return errors.Wrap(err, "Failed to check")
	}

	return nil
}
