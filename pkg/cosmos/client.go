package cosmos

import (
	"context"
	"fmt"

	rpcclient "github.com/cometbft/cometbft/rpc/jsonrpc/client"
	"github.com/ignite/cli/v28/ignite/pkg/cosmosaccount"
	"github.com/ignite/cli/v28/ignite/pkg/cosmosclient"
	"github.com/sourcenetwork/orbis-go/config"
)

type Client struct {
	cosmosclient.Client
	Account   cosmosaccount.Account
	Address   string
	RpcClient *rpcclient.WSClient
}

func New(ctx context.Context, cfg config.Cosmos) (*Client, error) {
	opts := []cosmosclient.Option{
		cosmosclient.WithNodeAddress(cfg.RPCAddress),
		cosmosclient.WithAddressPrefix(cfg.AddressPrefix),
		cosmosclient.WithFees(cfg.Fees),
		cosmosclient.WithKeyringBackend(cosmosaccount.KeyringBackend("test")), // TODO
	}
	client, err := cosmosclient.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("new cosmos client: %w", err)
	}

	account, err := client.Account(cfg.AccountName)
	if err != nil {
		return nil, fmt.Errorf("get account by name: %w", err)
	}

	address, err := account.Address(cfg.AddressPrefix)
	if err != nil {
		return nil, fmt.Errorf("get account address: %w", err)
	}

	rpcClient, err := rpcclient.NewWS(cfg.RPCAddress, "/websocket")
	if err != nil {
		return nil, fmt.Errorf("new rpc client: %w", err)
	}

	err = rpcClient.Start()
	if err != nil {
		return nil, fmt.Errorf("rpc client start: %w", err)
	}

	return &Client{
		Client:    client,
		Account:   account,
		Address:   address,
		RpcClient: rpcClient,
	}, nil
}
