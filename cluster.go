package main

import (
	"fmt"
	"net/http"
	"os"
)

type Cluster struct {
	onFly   bool
	localId string
}

func NewCluster() *Cluster {

	c := &Cluster{}

	flyIoId := os.Getenv("FLY_ALLOC_ID")
	if flyIoId != "" {
		c.onFly = true
		c.localId = flyIoId
	} else {
		var err error
		c.localId, err = genRandomKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}
	}

	return c
}

func (c *Cluster) LocalId() string {
	return c.localId
}

func (c *Cluster) GetLocalId() string {
	return c.localId
}

// TODO: currently hits filesystem for every request. Might be able to listen
// for primary change events and only update periodically
func (c *Cluster) PrimaryHost() (string, error) {
	bytes, err := os.ReadFile("/litefs/.primary")
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (c *Cluster) RedirectOrForward(host string, w http.ResponseWriter, r *http.Request) bool {
	if c.onFly {
		// Running on fly.io. Set replay header and indicate we're done
		w.Header().Set("fly-replay", fmt.Sprintf("instance=%s", host))
		return true
	} else {
		// TODO: handle other cluster environments
	}
	return false
}
