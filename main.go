package main

import (
	"github.com/pkg/profile"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"log"
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

	log.SetFlags(0)

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

	app.Before = func(c *cli.Context) error {
		log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("%v", err)
	}
}
