package check

import (
	"github.com/gophercloud/gophercloud"
	"github.com/nlopes/slack"
	"github.com/takaishi/noguard_sg_checker/config"
	"github.com/takaishi/noguard_sg_checker/openstack"
	"github.com/urfave/cli"
	"log"
	"os"
)

func Start(c *cli.Context) error {

	slack_token := os.Getenv("SLACK_TOKEN")

	cfg, err := config.ReadConfigFile(c.String("config"))
	if err != nil {
		return err
	}
	cfg.DryRun = c.Bool("dry-run")
	cfg.SlackChannel = os.Getenv("SLACK_CHANNEL_NAME")

	api := slack.New(slack_token)
	rtm := api.NewRTM()
	go rtm.ManageConnection()

	cfg.OpenStack.AuthURL = os.Getenv("OS_AUTH_URL")
	cfg.OpenStack.Username = os.Getenv("OS_USERNAME")
	cfg.OpenStack.Password = os.Getenv("OS_PASSWORD")
	cfg.OpenStack.RegionName = os.Getenv("OS_REGION_NAME")
	cfg.OpenStack.ProjectName = os.Getenv("OS_PROJECT_NAME")
	cfg.OpenStack.Cert = os.Getenv("OS_CERT")
	cfg.OpenStack.Key = os.Getenv("OS_KEY")

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

	err = checker.CheckSecurityGroups()
	if err != nil {
		log.Printf("[ERROR] %+v\n", err)
	}

	return nil
}
