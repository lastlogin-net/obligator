package obligator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type Proxy interface {
	AddDomain(domain string) error
}

func NewProxy(type_ string) Proxy {
	switch type_ {
	case "fly.io":
		return NewFlyIoProxy()
	case "caddy":
		return NewCaddyProxy()
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
}

func NewCaddyProxy() *CaddyProxy {
	return &CaddyProxy{}
}

func (p *CaddyProxy) AddDomain(domain string) error {
	return nil
}
