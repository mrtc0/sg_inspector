package main

import (
	"errors"
	"fmt"
	"github.com/gophercloud/gophercloud"
	"github.com/nlopes/slack"
	"github.com/robfig/cron"
	"github.com/takaishi/noguard_sg_checker/config"
	"github.com/takaishi/noguard_sg_checker/openstack"
	"github.com/urfave/cli"
	"log"
	"os"
	"strconv"
)

var version string

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config, c",
			Value: "config.toml",
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

	server := cron.New()
	server.AddFunc(checker.Cfg.CheckInterval, func() { checker.CheckSecurityGroups() })
	server.AddFunc("0 0 10 * * *", func() {
		log.Printf("一時的に許可していたSGをリセットします")
		checker.Cfg.TemporaryAllowdSecurityGroups = []string{}
	})
	go server.Run()

	for {
		select {
		case msg := <-rtm.IncomingEvents:
			switch ev := msg.Data.(type) {
			case *slack.HelloEvent:
				log.Print("Hello event")
			case *slack.InvalidAuthEvent:
				log.Print("Invalid credentials")
				return errors.New("Invalid credentials")
			case *slack.ReactionAddedEvent:
				if ev.Reaction == "white_check_mark" {
					log.Printf("%v\n", ev)
					ts, err := strconv.ParseFloat(ev.Item.Timestamp, 64)
					if err != nil {
						return err
					}
					log.Printf("%f\n", ts)
					log.Printf("%d\n", int(ts))
					param := slack.HistoryParameters{
						Latest:    "",
						Oldest:    fmt.Sprintf("%d", int(ts)),
						Count:     10,
						Inclusive: false,
						Unreads:   true,
					}
					history, err := api.GetChannelHistory(ev.Item.Channel, param)
					if err != nil {
						return err
					}
					for _, msg := range history.Messages {
						if msg.Timestamp == ev.Item.Timestamp {
							for _, f := range msg.Attachments[0].Fields {
								if f.Title == "ID" {
									log.Printf("%+v\n", f.Value)
									checker.Cfg.TemporaryAllowdSecurityGroups = append(checker.Cfg.TemporaryAllowdSecurityGroups, f.Value)
									log.Printf("%+v\n", checker.Cfg.TemporaryAllowdSecurityGroups)
								}
							}
						}
					}
				}
			}
		}
	}

	return nil
}
