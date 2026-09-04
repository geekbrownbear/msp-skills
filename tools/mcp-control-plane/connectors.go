package main

import (
	"os"
	"strings"
)

// CPConnector is a connector the control plane can grant access to. The list
// defaults to the known fleet and can be overridden with CONTROL_PLANE_CONNECTORS
// (comma-separated slugs); later it can be synced live from the gateway.
type CPConnector struct {
	Slug string
	Name string
}

var defaultConnectors = []CPConnector{
	{"auvik", "Auvik"},
	{"avanan", "Avanan"},
	{"cipp", "CIPP"},
	{"cork", "Cork"},
	{"datto-bcdr", "Datto BCDR"},
	{"halopsa", "HaloPSA"},
	{"hubspot", "HubSpot"},
	{"hudu", "Hudu"},
	{"huntress", "Huntress"},
	{"immybot", "ImmyBot"},
	{"ninjaone", "NinjaOne"},
	{"quickbooks", "QuickBooks Online"},
	{"sherweb", "Sherweb"},
	{"threatlocker", "ThreatLocker"},
}

func connectors() []CPConnector {
	if env := strings.TrimSpace(os.Getenv("CONTROL_PLANE_CONNECTORS")); env != "" {
		var out []CPConnector
		for _, s := range strings.Split(env, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, CPConnector{Slug: s, Name: s})
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return defaultConnectors
}
