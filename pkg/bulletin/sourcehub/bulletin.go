package sourcehub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	logging "github.com/ipfs/go-log"
	"google.golang.org/protobuf/proto"

	eventbus "github.com/sourcenetwork/eventbus-go"

	"github.com/sourcenetwork/orbis-go/config"
	sourcehubbulletinv1alpha1 "github.com/sourcenetwork/orbis-go/gen/proto/orbis/bulletin/sourcehub/v1alpha1"
	transportv1alpha1 "github.com/sourcenetwork/orbis-go/gen/proto/orbis/transport/v1alpha1"
	"github.com/sourcenetwork/orbis-go/pkg/bulletin"
	"github.com/sourcenetwork/orbis-go/pkg/cosmos"
	"github.com/sourcenetwork/orbis-go/pkg/host"
	"github.com/sourcenetwork/orbis-go/pkg/transport"

	"github.com/sourcenetwork/sourcehub/x/bulletin/types"

	"github.com/cometbft/cometbft/libs/bytes"
	rpctypes "github.com/cometbft/cometbft/rpc/core/types"
)

var log = logging.Logger("orbis/bulletin/sourcehub")

const name = "sourcehub"

var _ bulletin.Bulletin = (*Bulletin)(nil)

type Bulletin struct {
	cfg config.Bulletin

	client *cosmos.Client
	bus    eventbus.Bus
}

func New(ctx context.Context, host *host.Host, client *cosmos.Client, cfg config.Bulletin) (*Bulletin, error) {

	bb := &Bulletin{
		cfg:    cfg,
		client: client,
	}

	return bb, nil
}

func (bb *Bulletin) Name() string {
	return name
}

func (bb *Bulletin) Init(ctx context.Context) error {
	err := bb.client.RpcClient.Subscribe(ctx, "tm.event='Tx' AND NewPost.payload EXISTS")
	if err != nil {
		return fmt.Errorf("subscribe to namespace: %w", err)
	}

	bb.bus = eventbus.NewBus()

	go bb.HandleEvents()

	return nil
}

func (bb *Bulletin) Register(ctx context.Context, namespace string) error {
	if namespace == "" {
		return bulletin.ErrEmptyNamespace
	}

	return nil
}

func (bb *Bulletin) Post(ctx context.Context, namespace, id string, msg *transport.Message) (bulletin.Response, error) {
	var resp bulletin.Response

	payload, err := proto.Marshal(msg)
	if err != nil {
		return bulletin.Response{}, fmt.Errorf("marshal post message payload: %w", err)
	}

	id = namespace + id
	hubMsg := &types.MsgCreatePost{
		Creator:   bb.client.Address,
		Namespace: id,
		Payload:   payload,
		Proof:     nil,
	}

	resp.Data = msg
	resp.ID = id

	_, err = bb.client.BroadcastTx(ctx, bb.client.Account, hubMsg)
	if err != nil {
		return resp, fmt.Errorf("broadcast tx: %w", err)
	}
	log.Infof("Posted to bulletin, namespace: %s", id)

	return resp, nil
}

func (bb *Bulletin) Read(ctx context.Context, namespace, id string) (bulletin.Response, error) {
	var resp bulletin.Response

	queryClient := types.NewQueryClient(bb.client.Context())
	id = namespace + id
	in := &types.QueryReadPostRequest{
		Namespace: id,
	}

	queryResp, err := queryClient.ReadPost(ctx, in)
	if err != nil {
		return resp, fmt.Errorf("query read post: %w", err)
	}

	var pbPayload transportv1alpha1.Message
	err = proto.Unmarshal(queryResp.Post.Payload, &pbPayload)
	if err != nil {
		return bulletin.Response{}, fmt.Errorf("unmarshal message payload: %w", err)
	}

	resp.Data = &pbPayload
	resp.ID = id

	return resp, nil
}

func (bb *Bulletin) Query(ctx context.Context, namespace, query string) (<-chan bulletin.QueryResponse, error) {
	if query == "" {
		return nil, fmt.Errorf("query can't be empty")
	}

	path := "store/bulletin/subspace"
	prefix := fmt.Sprintf("%s/%s", "Post/Value/", namespace)
	resp, err := bb.client.RPC.ABCIQuery(ctx, path, bytes.HexBytes(prefix))
	if err != nil {
		return nil, fmt.Errorf("ABCI Query: %w", err)
	}

	var KVPairs sourcehubbulletinv1alpha1.Pairs
	err = proto.Unmarshal(resp.Response.Value, &KVPairs)
	if err != nil {
		return nil, fmt.Errorf("kv pairs unmarshal: %w", err)
	}

	return nil, nil

}

func (bb *Bulletin) Verify(context.Context, bulletin.Proof, string, bulletin.Message) bool {
	return true
}

func (bb *Bulletin) Events() eventbus.Bus {
	return bb.bus
}

func (bb *Bulletin) HandleEvents() {

	for resp := range bb.client.RpcClient.ResponsesCh {
		result := &rpctypes.ResultEvent{}
		err := json.Unmarshal((resp.Result), result)
		if err != nil {
			log.Warnf("coud not unmarshal events resp: %v", err)
		}

		attrNamespace, ok := result.Events["NewPost.namespace"]
		if !ok {
			continue
		}
		attrPayload, ok := result.Events["NewPost.payload"]
		if !ok {
			continue
		}
		namespace := attrNamespace[0]
		b64Msg := attrPayload[0]
		rawMsg, err := base64.StdEncoding.DecodeString(b64Msg)
		if err != nil {
			log.Warnf("coud not decode base64 payload: %v", err)
			continue
		}

		var msg transportv1alpha1.Message
		if err := proto.Unmarshal(rawMsg, &msg); err != nil {
			log.Warnf("coud not unmarshal payload: %v", err)
			continue
		}

		evt := bulletin.Event{
			Message: &msg,
			ID:      namespace,
		}

		err = eventbus.Publish(bb.bus, evt)
		if err != nil {
			log.Warnf("failed to publish event to channel: %w", err)
			continue
		}
	}
}
