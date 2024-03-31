package acp

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/sourcenetwork/orbis-go/config"
	"github.com/sourcenetwork/orbis-go/pkg/authz"
	"github.com/sourcenetwork/orbis-go/pkg/cosmos"
	"github.com/sourcenetwork/sourcehub/x/acp/types"
)

var permRegex = `^(?P<PolicyID>\w+)\/(?P<ResourceGroup>\w+):(?P<ResourceID>\w+)#(?P<Relation>\w+)$`

type acp struct {
	client *cosmos.Client
}

func New(ctx context.Context, client *cosmos.Client, cfg config.Bulletin) (authz.Authz, error) {
	return newACPClient(ctx, client, cfg)
}

func newACPClient(ctx context.Context, client *cosmos.Client, cfg config.Bulletin) (*acp, error) {
	return nil, nil
}

func (a *acp) Init(ctx context.Context) error {
	return nil
}

func (a *acp) Name() string {
	return "ACP"
}

func (a *acp) Check(ctx context.Context, permission, subject string) (bool, error) {
	checkReq, err := parsePermToCheckRequest(permission)
	if err != nil {
		return false, fmt.Errorf("parse permission: %w", err)
	}

	subjects := strings.SplitN(subject, ":", 2)
	if len(subjects) != 2 {
		return false, fmt.Errorf("subject validation: %s (%v size=%d)", subject, subjects, len(subjects))
	}

	verifyReq := &types.QueryVerifyAccessRequestRequest{
		PolicyId: checkReq.policyID,
		AccessRequest: &types.AccessRequest{
			Operations: []*types.Operation{
				{
					Object:     types.NewObject(checkReq.ObjectGroup, checkReq.ObjectID),
					Permission: checkReq.relation,
				},
			},
			Actor: &types.Actor{
				Id: subjects[1],
			},
		},
	}

	queryClient := types.NewQueryClient(a.client.Context())
	resp, err := queryClient.VerifyAccessRequest(ctx, verifyReq)
	if err != nil {
		return false, fmt.Errorf("query: %w", err)
	}

	return resp.Valid, nil
}

type checkRequest struct {
	policyID    string
	ObjectGroup string
	ObjectID    string
	relation    string
}

// permission is formatted as:
// PolicyID/ObjGroup:ObjID#relation
// we need to parse out:
// - PolicyID
// - ObjGroup
// - ObjID
// - relation
func parsePermToCheckRequest(permission string) (checkRequest, error) {
	r, err := regexp.Compile(permRegex)
	if err != nil {
		return checkRequest{}, err
	}

	if !r.Match([]byte(permission)) {
		return checkRequest{}, fmt.Errorf("permission validation: %s", permission)
	}

	results := r.FindStringSubmatch(permission)
	fmt.Println(results)
	if len(results) != 5 {
		return checkRequest{}, fmt.Errorf("regex submatch size: %d", len(results))
	}
	// return &types.QueryVerifyAccessRequestRequest{
	// 	PolicyId: results[1],
	// 	AccessRequest: &types.AccessRequest{
	// 		Object:   domain.NewEntity(results[2], results[3]),
	// 		Relation: results[4],
	// 	},
	// }, nil

	// return &types.QueryVerifyAccessRequestRequest{
	// 	PolicyId: results[1],
	// 	AccessRequest: &types.AccessRequest{
	// 		Operations: []*types.Operation{
	// 			{
	// 				Object: types.NewObject(results[2], results[3]),
	// 				Permission: results[4],
	// 			},
	// 		},
	// 		Actor: &types.Actor{
	// 			Id: ,
	// 		},
	// 	},
	// }, nil

	return checkRequest{
		policyID:    results[1],
		ObjectGroup: results[2],
		ObjectID:    results[3],
		relation:    results[4],
	}, nil
}
