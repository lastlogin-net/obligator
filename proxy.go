package obligator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

type Proxy interface {
	AddDomain(domain string) error
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

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		msg := fmt.Sprintf("Adding domain to fly.io failed: %s", string(body))
		return errors.New(msg)
	}

	var graphQlMsg GraphQLMessage

	err = json.Unmarshal(body, &graphQlMsg)
	if err != nil {
		return err
	}

	if len(graphQlMsg.Errors) > 0 {
		return errors.New(graphQlMsg.Errors[0].Message)
	}

	return nil
}

type GraphQLMessage struct {
	Errors []*GraphQLError `json:"errors"`
}

type GraphQLError struct {
	Message string `json:"message"`
}

type CaddyProxy struct {
	httpClient *http.Client
	serverUri  string
	serverName string
	port       int
	id         string
}

func NewCaddyProxy(serverName string, port int, prefix string) *CaddyProxy {
	serverUri := "http://localhost:2019"

	id := fmt.Sprintf("%sroute", prefix)

	route := Route{
		Id: id,
		Handle: []Handle{
			Handle{
				Handler: "reverse_proxy",
				Upstreams: []Upstream{
					Upstream{
						Dial: fmt.Sprintf("localhost:%d", port),
					},
				},
			},
		},
		Match: []Match{},
	}

	p := &CaddyProxy{
		httpClient: &http.Client{},
		serverUri:  serverUri,
		serverName: serverName,
		port:       port,
		id:         id,
	}

	path := fmt.Sprintf("/id/%s/match", id)
	err := p.request("PATCH", path, []Match{})
	if err != nil {
		path := fmt.Sprintf("/config/apps/http/servers/%s/routes", serverName)
		err := p.request("POST", path, route)
		if err != nil {
			panic(err)
		}
	}

	return p
}

func (p *CaddyProxy) AddDomain(domain string) error {

	match := Match{
		Host: []string{domain},
	}

	path := fmt.Sprintf("/id/%s/match", p.id)
	err := p.request("POST", path, match)
	if err != nil {
		return err
	}

	return nil
}

func (p *CaddyProxy) request(method string, path string, data interface{}) error {

	dataJson, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return p.requestBytes(method, path, dataJson)
}

func (p *CaddyProxy) requestBytes(method string, path string, data []byte) error {

	uri := fmt.Sprintf("%s%s", p.serverUri, path)

	req, err := http.NewRequest(method, uri, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("Bad code")
	}

	return nil
}

// Caddy types. Copied from https://github.com/multisig-labs/caddyapi/blob/main/types.go

type Route struct {
	Id       string   `json:"@id,omitempty"`
	Handle   []Handle `json:"handle"`
	Match    []Match  `json:"match"`
	Terminal bool     `json:"terminal"`
}

type Match struct {
	Host []string `json:"host,omitempty"`
	Path []string `json:"path,omitempty"`
}

type Handle struct {
	Id        string     `json:"@id,omitempty"`
	Handler   string     `json:"handler"`
	Routes    []Route    `json:"routes,omitempty"`
	Upstreams []Upstream `json:"upstreams,omitempty"`
}

type Upstream struct {
	Dial string `json:"dial"`
}
