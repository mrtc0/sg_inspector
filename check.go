package main

import (
	"github.com/pkg/errors"
	"github.com/slack-go/slack"
	"github.com/urfave/cli"
	"os"
)

func StartCheck(c *cli.Context) error {
	cfg, err := ReadConfig(c.String("config"), c.Bool("dry-run"))
	if err != nil {
		return err
	}

	api := slack.New(cfg.SlackToken)
	if os.Getenv("DEBUG") != "" {
		slack.OptionDebug(true)(api)
	}

	if err := NewOpenStackChecker(cfg, api).Run(); err != nil {
		return errors.Wrap(err, "Failed to check")
	}

	return nil
}
