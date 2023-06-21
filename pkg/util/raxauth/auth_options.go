package raxauth

import (
	"fmt"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	tokens2 "github.com/gophercloud/gophercloud/openstack/identity/v2/tokens"
)

// ApiKeyCredentialsV2 represents the required options to authenticate
// with a Rackspace API key
type ApiKeyCredentialsV2 struct {
	Username string `json:"username" required:"true"`
	ApiKey   string `json:"apiKey" required:"true"`
}

// AuthOptions are the valid options for Openstack Identity v2 authentication.
// For field descriptions, see gophercloud.AuthOptions.
type AuthOptions struct {
	IdentityEndpoint string `json:"-"`
	Username         string `json:"username,omitempty"`
	Password         string `json:"password,omitempty"`
	ApiKey           string `json:"apiKey,omitempty"`
	TenantID         string `json:"tenantId,omitempty"`
	TenantName       string `json:"tenantName,omitempty"`
	AllowReauth      bool   `json:"-"`
	TokenID          string
}

// AuthOptionsV2 wraps a gophercloud AuthOptions in order to adhere to the
// AuthOptionsBuilder interface.
type AuthOptionsV2 struct {
	PasswordCredentials *tokens2.PasswordCredentialsV2 `json:"passwordCredentials,omitempty"`

	// TokenCredentials allows users to authenticate (possibly as another user)
	// with an authentication token ID.
	TokenCredentials *tokens2.TokenCredentialsV2 `json:"token,omitempty"`

	// ApiKeyCredentials allows users to authenticate with a Rackspace API key
	ApiKeyCredentials *ApiKeyCredentialsV2 `json:"RAX-KSKEY:apiKeyCredentials,omitempty"`
}

// ToTokenV2CreateMap allows AuthOptions to satisfy the AuthOptionsBuilder
// interface in the v2 tokens package
func (opts AuthOptions) ToTokenV2CreateMap() (map[string]interface{}, error) {
	// Populate the request map.
	v2Opts := AuthOptionsV2{}

	if opts.ApiKey != "" {
		if opts.Username == "" {
			return nil, fmt.Errorf("username must be supplied for API key auth")
		}
		v2Opts.ApiKeyCredentials = &ApiKeyCredentialsV2{
			Username: opts.Username,
			ApiKey:   opts.ApiKey,
		}
	} else if opts.Password != "" {
		if opts.Username == "" {
			return nil, fmt.Errorf("username must be supplied for password auth")
		}
		v2Opts.PasswordCredentials = &tokens2.PasswordCredentialsV2{
			Username: opts.Username,
			Password: opts.Password,
		}
	} else if opts.TokenID != "" {
		v2Opts.TokenCredentials = &tokens2.TokenCredentialsV2{
			ID: opts.TokenID,
		}
	} else {
		return nil, fmt.Errorf("missing username/password/apiKey or tokenId for auth")
	}

	b, err := gophercloud.BuildRequestBody(v2Opts, "auth")
	if err != nil {
		return nil, fmt.Errorf("unable to create auth request: %v", err)
	}
	return b, nil
}

func Authenticate(client *gophercloud.ProviderClient, options AuthOptions, eo gophercloud.EndpointOpts) error {
	v2Client, err := openstack.NewIdentityV2(client, eo)
	if err != nil {
		return err
	}

	result := tokens2.Create(v2Client, options)

	err = client.SetTokenAndAuthResult(result)
	if err != nil {
		return err
	}

	catalog, err := result.ExtractServiceCatalog()
	if err != nil {
		return err
	}

	if options.AllowReauth {
		// here we're creating a throw-away client (tac). it's a copy of the user's provider client, but
		// with the token and reauth func zeroed out. combined with setting `AllowReauth` to `false`,
		// this should retry authentication only once
		tac := *client
		tac.SetThrowaway(true)
		tac.ReauthFunc = nil
		tac.SetTokenAndAuthResult(nil)
		tao := options
		tao.AllowReauth = false
		client.ReauthFunc = func() error {
			err := Authenticate(&tac, tao, eo)
			if err != nil {
				return err
			}
			client.CopyTokenFrom(&tac)
			return nil
		}
	}
	client.EndpointLocator = func(opts gophercloud.EndpointOpts) (string, error) {
		return openstack.V2EndpointURL(catalog, opts)
	}

	return nil
}
