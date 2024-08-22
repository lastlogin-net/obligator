package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/lastlogin-io/obligator"
)

func main() {

	configArg := flag.String("config", "", "Config path")
	port := flag.Int("port", 1616, "Port")
	prefix := flag.String("prefix", "obligator_", "Prefix for files and cookies")
	dbDir := flag.String("database-dir", "./", "Database directory")
	apiSocketDir := flag.String("api-socket-dir", "./", "API socket directory")
	behindProxy := flag.Bool("behind-proxy", false, "Whether we are behind a reverse proxy")
	displayName := flag.String("display-name", "obligator", "Display name")
	geoDbPath := flag.String("geo-db-path", "", "IP2Location Geo DB file")
	forwardAuthPassthrough := flag.Bool("forward-auth-passthrough", false, "Always return success for validation requests")
	proxyType := flag.String("proxy-type", "builtin", "Proxy type")

	var domains obligator.StringList
	flag.Var(&domains, "domain", "Domains - can provide multiple times")
	var users obligator.StringList
	flag.Var(&users, "user", "Users - can provide multiple times")

	flag.Parse()

	configPath := *configArg

	var config *obligator.ServerConfig

	if configPath != "" {
		configJson, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read config\n")
			os.Exit(1)
		}

		err = json.Unmarshal(configJson, &config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed parse JSON\n")
			os.Exit(1)
		}
	}

	conf := obligator.ServerConfig{
		Port:                   *port,
		Prefix:                 *prefix,
		DatabaseDir:            *dbDir,
		ApiSocketDir:           *apiSocketDir,
		BehindProxy:            *behindProxy,
		DisplayName:            *displayName,
		GeoDbPath:              *geoDbPath,
		ForwardAuthPassthrough: *forwardAuthPassthrough,
		Domains:                domains,
		Users:                  users,
		ProxyType:              *proxyType,
	}

	if config != nil {
		if config.OAuth2Providers != nil {
			conf.OAuth2Providers = config.OAuth2Providers
		}
		if config.Smtp != nil {
			conf.Smtp = config.Smtp
		}
	}

	server := obligator.NewServer(conf)
	server.Start()
}
