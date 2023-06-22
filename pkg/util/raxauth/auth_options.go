package raxauth

import (
	"fmt"

	tokens2 "github.com/gophercloud/gophercloud/openstack/identity/v2/tokens"
)

// AuthOptions are the valid options for Openstack Identity v2 authentication.
// For field descriptions, see gophercloud.AuthOptions.
type AuthOptionsRax struct {
	tokens2.AuthOptions
	ApiKey string `json:"apiKey,omitempty"`
}

// ToTokenV2CreateMap allows AuthOptions to satisfy the AuthOptionsBuilder
// interface in the v2 tokens package
func (opts AuthOptionsRax) ToTokenV2CreateMap() (map[string]interface{}, error) {

	// if we have an ApiKey, use that otherwise just use the regular auth mechanism
	if opts.ApiKey != "" {
		if opts.Username == "" {
			return nil, fmt.Errorf("username must be supplied for API key auth")
		}

		return map[string]interface{}{
			"auth": map[string]interface{}{
				"RAX-KSKEY:apiKeyCredentials": map[string]interface{}{
					"username": opts.AuthOptions.Username,
					"apiKey":   opts.ApiKey,
				},
			},
		}, nil
	} else if opts.AuthOptions.Username != "" || opts.AuthOptions.TokenID != "" {
		return opts.AuthOptions.ToTokenV2CreateMap()
	} else {
		return nil, fmt.Errorf("missing username/password/apiKey or tokenId for auth")
	}
}
