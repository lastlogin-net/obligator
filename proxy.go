package obligator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/multisig-labs/caddyapi"
)

type Proxy interface {
	AddDomain(domain string) error
}

func NewProxy(type_ string, port int) Proxy {
	switch type_ {
	case "fly.io":
		return NewFlyIoProxy()
	case "caddy":
		return NewCaddyProxy(port)
	default:
		return nil
	}
}

type FlyIoProxy struct {
	token      string
	appId      string
	httpClient *http.Client
}

func NewFlyIoProxy() *FlyIoProxy {

	token := os.Getenv("FLY_IO_TOKEN")
	appId := os.Getenv("FLY_IO_APP_ID")

	httpClient := &http.Client{}

	return &FlyIoProxy{
		token:      token,
		appId:      appId,
		httpClient: httpClient,
	}
}

func (p *FlyIoProxy) AddDomain(domain string) error {
	queryJsonMap := map[string]string{
		"query": fmt.Sprintf(`
                        mutation {
                                addCertificate(appId: "%s", hostname: "%s") {
                                        certificate {
                                                hostname
                                        }
                                }
                        }
                `, p.appId, domain),
	}

	queryJson, err := json.Marshal(queryJsonMap)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.fly.io/graphql", bytes.NewBuffer(queryJson))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+p.token)

	res, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	fmt.Println(res.StatusCode)

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	fmt.Println(string(body))

	return nil
}

type CaddyProxy struct {
	api    *caddyapi.CaddyAPI
	config caddyapi.Config
}

func NewCaddyProxy(port int) *CaddyProxy {
	api := caddyapi.NewCaddyAPI("http://localhost:2019")

	routes := []caddyapi.Route{
		caddyapi.Route{
			Handle: []caddyapi.Handle{
				caddyapi.Handle{
					Handler: "reverse_proxy",
					Upstreams: []caddyapi.Upstream{
						caddyapi.Upstream{
							Dial: fmt.Sprintf("localhost:%d", port),
						},
					},
				},
			},
			Match: []caddyapi.Match{
				caddyapi.Match{
					Host: []string{},
				},
			},
		},
	}

	config := caddyapi.Config{
		Apps: caddyapi.Apps{
			HTTP: caddyapi.HTTP{
				Servers: map[string]caddyapi.Server{
					"obligator": caddyapi.Server{
						Listen: []string{
							":443",
						},
						Routes: routes,
					},
				},
			},
		},
	}

	err := api.LoadConfig(config)
	if err != nil {
		panic(err)
	}

	return &CaddyProxy{
		api,
		config,
	}
}

func (p *CaddyProxy) AddDomain(domain string) error {

	match := &p.config.Apps.HTTP.Servers["obligator"].Routes[0].Match[0]
	(*match).Host = append((*match).Host, domain)

	return p.api.LoadConfig(p.config)
}
