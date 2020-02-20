package main

import (
	"github.com/pkg/profile"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
)

var version string

func init() {
	if os.Getenv("DEBUG") != "" {
		logrus.SetLevel(logrus.DebugLevel)
	}
}

func main() {
	if os.Getenv("PROFILE") != "" {
		defer profile.Start(profile.CPUProfile, profile.ProfilePath("."), profile.NoShutdownHook).Stop()
	}

	app := cli.NewApp()
	app.Version = Version
	app.Commands = []cli.Command{
		{
			Name:  "server",
			Usage: "",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "config, c",
					Value: "config.toml",
				},
				cli.BoolFlag{
					Name:   "dry-run",
					Usage:  "when this is true, does't post message to slack",
					Hidden: false,
				},
			},
			Action: func(c *cli.Context) error {
				return StartServer(c)
			},
		},
		{
			Name:  "check",
			Usage: "",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "config, c",
					Value: "config.toml",
				},
				cli.BoolFlag{
					Name:   "dry-run",
					Usage:  "when this is true, does't post message to slack",
					Hidden: false,
				},
			},
			Action: func(c *cli.Context) error {
				return StartCheck(c)
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logrus.Error("%+v", err)
		os.Exit(1)
	}
	os.Exit(0)
}
