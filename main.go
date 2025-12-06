package main

import (
	"os"

	"github.com/falcn-io/falcn/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}


