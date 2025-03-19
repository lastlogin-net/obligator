package obligator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type OAuth2MetadataManager struct {
	db             Database
	oidcConfigs    map[string]*OAuth2ServerMetadata
	jwksRefreshers map[string]*jwk.Cache
	mut            *sync.Mutex
}

func NewOAuth2MetadataManager(db Database) *OAuth2MetadataManager {
	m := &OAuth2MetadataManager{
		db:          db,
		oidcConfigs: make(map[string]*OAuth2ServerMetadata),
		mut:         &sync.Mutex{},
	}

	return m
}

func (m *OAuth2MetadataManager) GetMeta(providerId string) (*OAuth2ServerMetadata, error) {
	m.mut.Lock()
	defer m.mut.Unlock()

	if meta, exists := m.oidcConfigs[providerId]; exists {
		return &(*meta), nil
	}

	return nil, errors.New("No such provider")
}

func (m *OAuth2MetadataManager) GetKeyset(providerId string) (jwk.Set, error) {
	m.mut.Lock()
	defer m.mut.Unlock()

	ctx := context.Background()

	keyset, err := m.jwksRefreshers[providerId].Get(ctx, m.oidcConfigs[providerId].JwksUri)
	if err != nil {
		return nil, err
	}

	return keyset, nil
}

func (m *OAuth2MetadataManager) Update() error {

	// TODO: Make this more robust. We're holding the lock until the update
	// completes. It will either succeed or we exit
	m.mut.Lock()

	go func() {
		defer m.mut.Unlock()

		m.oidcConfigs = make(map[string]*OAuth2ServerMetadata)
		m.jwksRefreshers = make(map[string]*jwk.Cache)

		ctx := context.Background()

		providers, err := m.db.GetOAuth2Providers()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		for _, oidcProvider := range providers {
			if !oidcProvider.OpenIDConnect {
				continue
			}

			var err error
			m.oidcConfigs[oidcProvider.ID], err = GetOidcConfiguration(oidcProvider.URI)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get OIDC config for "+oidcProvider.URI)
				os.Exit(1)
			}

			m.jwksRefreshers[oidcProvider.ID] = jwk.NewCache(ctx)
			m.jwksRefreshers[oidcProvider.ID].Register(m.oidcConfigs[oidcProvider.ID].JwksUri)

			_, err = m.jwksRefreshers[oidcProvider.ID].Refresh(ctx, m.oidcConfigs[oidcProvider.ID].JwksUri)
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
		}

	}()

	return nil
}
