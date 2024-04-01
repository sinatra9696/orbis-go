package acp

import (
	"context"

	"github.com/samber/do"

	"github.com/sourcenetwork/orbis-go/config"
	"github.com/sourcenetwork/orbis-go/pkg/authz"
	"github.com/sourcenetwork/orbis-go/pkg/cosmos"
	odb "github.com/sourcenetwork/orbis-go/pkg/db"
	"github.com/sourcenetwork/orbis-go/pkg/types"
)

var (
	_       types.Factory[authz.Authz] = (*factory)(nil)
	Factory                            = factory{}
)

type factory struct{}

func (factory) New(inj *do.Injector, rkeys []odb.RepoKey, cfg config.Config) (authz.Authz, error) {
	cc, err := do.Invoke[*cosmos.Client](inj)
	if err != nil {
		return nil, err
	}
	return New(context.TODO(), cc)
}

func (factory) Name() string {
	return name
}

func (factory) Repos() []string {
	return []string{}
}
