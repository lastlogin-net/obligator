package main

import (
	"flag"

	"github.com/lastlogin-io/obligator"
)

func main() {

	port := flag.Int("port", 1616, "Port")
	rootUri := flag.String("root-uri", "", "Root URI")
	prefix := flag.String("prefix", "obligator_", "Prefix for files and cookies")
	storageDir := flag.String("storage-dir", "./", "Storage directory")
	dbDir := flag.String("database-dir", "./", "Database directory")
	apiSocketDir := flag.String("api-socket-dir", "./", "API socket directory")
	behindProxy := flag.Bool("behind-proxy", false, "Whether we are behind a reverse proxy")
	displayName := flag.String("display-name", "obligator", "Display name")
	geoDbPath := flag.String("geo-db-path", "", "IP2Location Geo DB file")
	fedCm := flag.Bool("fedcm", false, "Enable FedCM support")
	forwardAuthPassthrough := flag.Bool("forward-auth-passthrough", false, "Always return success for validation requests")
	flag.Parse()

	conf := obligator.ServerConfig{
		Port:                   *port,
		RootUri:                *rootUri,
		Prefix:                 *prefix,
		StorageDir:             *storageDir,
		DatabaseDir:            *dbDir,
		ApiSocketDir:           *apiSocketDir,
		BehindProxy:            *behindProxy,
		DisplayName:            *displayName,
		GeoDbPath:              *geoDbPath,
		FedCm:                  *fedCm,
		ForwardAuthPassthrough: *forwardAuthPassthrough,
	}

	server := obligator.NewServer(conf)
	server.Start()
}
