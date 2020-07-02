package main

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/gophercloud/gophercloud"
	"github.com/pkg/errors"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
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

	if os.Getenv("DEBUG") != "" {
		slack.OptionDebug(true)(api)
	}
	rtm := api.NewRTM()
	go rtm.ManageConnection()

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

	redisClient := redis.NewClient(
		&redis.Options{
			Addr:     "localhost:6379",
			Password: "",
			DB:       0,
		})

	server := cron.New()
	server.AddFunc(checker.Cfg.ResetInterval, func() {
		logrus.Infof("一時的に許可していたSGをリセットします")
		_, err := redisClient.Del(context.Background(), REDIS_KEY).Result()
		if err != nil {
			logrus.Errorf("%+v\n", err)
		}
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
					logrus.Infof("%v\n", ev)
					ts, err := strconv.ParseFloat(ev.Item.Timestamp, 64)
					if err != nil {
						return err
					}
					logrus.Infof("%f\n", ts)
					logrus.Infof("%d\n", int(ts))
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
									logrus.Infof("%+v\n", f.Value)
									redisClient.LPush(context.Background(), REDIS_KEY, f.Value)
									params := slack.PostMessageParameters{
										Username:        checker.Cfg.Username,
										IconEmoji:       checker.Cfg.IconEmoji,
										ThreadTimestamp: ev.Item.Timestamp,
									}
									_, _, err := api.PostMessage(checker.Cfg.SlackChannel, slack.MsgOptionText("明日の10時までは許可しますね〜", false), slack.MsgOptionPostMessageParameters(params))
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
