package main

import (
	"os"

	"github.com/grafana/grafana-plugin-sdk-go/backend/app"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"

	"github.com/luiscorreiaops/brain-agent-app/pkg/plugin"
)

func main() {
	if err := app.Manage("shortbobcat2735-brainagent-app", plugin.NewApp, app.ManageOpts{}); err != nil {
		log.DefaultLogger.Error("Error running plugin", "error", err)
		os.Exit(1)
	}
}
