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

	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)
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

	checker := openstack.OpenStackSecurityGroupChecker{
		Cfg:         cfg,
		SlackClient: api,
		AuthOptions: opts,
		RegionName:  osRegionName,
		Cert:        osCert,
		Key:         osKey,
	}

	err = checker.CheckSecurityGroups()
	if err != nil {
		log.Printf("[ERROR] %+v\n", err)
	}

	return nil
}
