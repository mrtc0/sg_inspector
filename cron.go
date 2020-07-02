package main

import (
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

	checker := NewOpenStackChecker(cfg, api)

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
