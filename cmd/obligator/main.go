package main

import (
	"flag"

	"github.com/lastlogin-io/obligator"
)

func main() {

	port := flag.Int("port", 1616, "Port")
	prefix := flag.String("prefix", "obligator_", "Prefix for files and cookies")
	storageDir := flag.String("storage-dir", "./", "Storage directory")
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

	conf := obligator.ServerConfig{
		Port:                   *port,
		Prefix:                 *prefix,
		StorageDir:             *storageDir,
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

	server := obligator.NewServer(conf)
	server.Start()
}
