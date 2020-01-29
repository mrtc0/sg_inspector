package check

import (
	"github.com/gophercloud/gophercloud"
	"github.com/nlopes/slack"
	"github.com/pkg/errors"
	"github.com/takaishi/sg_inspector/config"
	"github.com/takaishi/sg_inspector/openstack"
	"github.com/urfave/cli"
)

func Start(c *cli.Context) error {
	cfg, err := config.ReadConfig(c.String("config"), c.Bool("dry-run"))
	if err != nil {
		return err
	}

	api := slack.New(cfg.SlackToken)

	opts := gophercloud.AuthOptions{
		IdentityEndpoint: cfg.OpenStack.AuthURL,
		Username:         cfg.OpenStack.Username,
		Password:         cfg.OpenStack.Password,
		DomainName:       "Default",
		TenantName:       cfg.OpenStack.ProjectName,
	}

	checker := openstack.OpenStackSecurityGroupChecker{
		Cfg:         cfg,
		SlackClient: api,
		AuthOptions: opts,
		RegionName:  cfg.OpenStack.RegionName,
		Cert:        cfg.OpenStack.Cert,
		Key:         cfg.OpenStack.Key,
	}

	err = checker.Run()
	if err != nil {
		return errors.Wrap(err, "Failed to check")
	}

	return nil
}
