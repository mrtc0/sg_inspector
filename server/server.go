package server

import (
	"fmt"
	"github.com/gophercloud/gophercloud"
	"github.com/nlopes/slack"
	"github.com/pkg/errors"
	"github.com/robfig/cron"
	"github.com/takaishi/noguard_sg_checker/config"
	"github.com/takaishi/noguard_sg_checker/openstack"
	"github.com/urfave/cli"
	"log"
	"os"
	"strconv"
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

	server := cron.New()
	server.AddFunc(checker.Cfg.CheckInterval, func() {
		err := checker.CheckSecurityGroups()
		if err != nil {
			log.Printf("[ERROR] %+v\n", err)
		}
	})
	server.AddFunc(checker.Cfg.ResetInterval, func() {
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
									params := slack.PostMessageParameters{
										Username:        checker.Cfg.Username,
										IconEmoji:       checker.Cfg.IconEmoji,
										ThreadTimestamp: ev.Item.Timestamp,
									}
									_, _, err := api.PostMessage(checker.Cfg.SlackChannel, "明日の10時までは許可しますね〜", params)
									if err != nil {
										return err
									}
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
