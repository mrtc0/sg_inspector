package main

import (
	"github.com/urfave/cli"
	"log"
	"os"
)

var version string

func main() {
	app := cli.NewApp()

	app.Action = func(c *cli.Context) error {
		log.Printf("[DEBUG] Hello World\n")
		return nil
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}