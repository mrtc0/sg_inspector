package main

import (
	"github.com/gophercloud/gophercloud"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/urfave/cli"
	"os"
)

func StartCron(c *cli.Context) error {
	logrus.Info("Start Cron.")
	cfg, err := ReadConfig(c.String("config"), c.Bool("dry-run"))
	if err != nil {
		return err
	}

	api := slack.New(cfg.SlackToken)

	if os.Getenv("DEBUG") != "" {
		slack.OptionDebug(true)(api)
	}

	opts := gophercloud.AuthOptions{
		IdentityEndpoint: cfg.OpenStack.AuthURL,
		Username:         cfg.OpenStack.Username,
		Password:         cfg.OpenStack.Password,
		DomainName:       "Default",
		TenantName:       cfg.OpenStack.ProjectName,
	}

	checker := OpenStackSecurityGroupChecker{
		Cfg:         cfg,
		SlackClient: api,
		AuthOptions: opts,
		RegionName:  cfg.OpenStack.RegionName,
		Cert:        cfg.OpenStack.Cert,
		Key:         cfg.OpenStack.Key,
	}

	server := cron.New()
	logrus.Infof("check intercal: %s", checker.Cfg.CheckInterval)
	server.AddFunc(checker.Cfg.CheckInterval, func() {
		err := checker.Run()
		if err != nil {
			logrus.Errorf("%+v\n", err)
		}
	})

	server.Run()

	return nil
}
