package main

import (
	"fmt"
	"github.com/gophercloud/gophercloud"
	"github.com/nlopes/slack"
	"github.com/pkg/errors"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
	"strconv"
)

type logProvider struct {
}

func (l *logProvider) Output(i int, s string) error {
	logrus.Debug(s)
	return nil
}

func StartServer(c *cli.Context) error {
	logrus.Info("Start Server.")
	cfg, err := ReadConfig(c.String("config"), c.Bool("dry-run"))
	if err != nil {
		return err
	}

	api := slack.New(cfg.SlackToken)

	slack.SetLogger(&logProvider{})
	if os.Getenv("DEBUG") != "" {
		api.SetDebug(true)
	}
	rtm := api.NewRTM()
	go rtm.ManageConnection()

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
	server.AddFunc(checker.Cfg.CheckInterval, func() {
		err := checker.Run()
		if err != nil {
			logrus.Error("%+v\n", err)
		}
	})
	server.AddFunc(checker.Cfg.ResetInterval, func() {
		logrus.Info("一時的に許可していたSGをリセットします")
		checker.Cfg.TemporaryAllowdSecurityGroups = []string{}
	})
	go server.Run()

	for {
		select {
		case msg := <-rtm.IncomingEvents:
			switch ev := msg.Data.(type) {
			case *slack.HelloEvent:
				logrus.Info("Hello event")
			case *slack.InvalidAuthEvent:
				logrus.Info("Invalid credentials")
				return errors.New("Invalid credentials")
			case *slack.ReactionAddedEvent:
				if ev.Reaction == "white_check_mark" {
					logrus.Info("%v\n", ev)
					ts, err := strconv.ParseFloat(ev.Item.Timestamp, 64)
					if err != nil {
						return err
					}
					logrus.Info("%f\n", ts)
					logrus.Info("%d\n", int(ts))
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
									logrus.Info("%+v\n", f.Value)
									checker.Cfg.TemporaryAllowdSecurityGroups = append(checker.Cfg.TemporaryAllowdSecurityGroups, f.Value)
									logrus.Info("%+v\n", checker.Cfg.TemporaryAllowdSecurityGroups)
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
