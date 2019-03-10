package main

import (
	"github.com/takaishi/noguard_sg_checker/check"
	"github.com/takaishi/noguard_sg_checker/server"
	"github.com/urfave/cli"
	"log"
	"os"
)

var version string

func main() {
	app := cli.NewApp()
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
				return server.Start(c)
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
				return check.Start(c)
			},
		},
	}

	app.Before = func(c *cli.Context) error {
		log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
