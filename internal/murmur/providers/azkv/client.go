package azkv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"net/http"
	"os"
	"encoding/json"
	"time"
	"strconv" 

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	// "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type client struct {
	credential azcore.TokenCredential

	mu           sync.RWMutex // Protects keyvaultClients
	vaultClients map[string]*azsecrets.Client
}

type accessToken azcore.AccessToken

func (a accessToken) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken(a), nil
}

// New returns a client that fetches secrets from Azure Key Vault.
func New() (*client, error) {
	// Get environment variables
	identityHeader := os.Getenv("IDENTITY_HEADER")
	identityEndpoint := os.Getenv("IDENTITY_ENDPOINT")

	// Check if environment variables are defined
	if identityHeader == "" || identityEndpoint == "" {
		return nil, fmt.Errorf("IDENTITY_HEADER or IDENTITY_ENDPOINT is not defined.")
	}

	// Create HTTP request
	url := fmt.Sprintf("%s?resource=https://vault.azure.net&api-version=2019-08-01", identityEndpoint)
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("x-identity-header", identityHeader)
	reqClient := &http.Client{}
	resp, err := reqClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Can not get managed identity token:", err)
	}
	defer resp.Body.Close()

	// Get access token
	var responseBody map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&responseBody)
	if err != nil {
		return nil, fmt.Errorf("Error when parsing JSON response:", err)
	}
	accessTokenResp, ok := responseBody["access_token"].(string)
	if !ok {
		return nil, fmt.Errorf("Access token is missing")
	}
	expTimeResp, ok := responseBody["expires_on"].(string)
	if !ok {
		return nil, fmt.Errorf("Expiration time is missing")
	}
	expiresOnUnix, err := strconv.ParseInt(expTimeResp, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Error when converting expires_on in int64:", err)
	}
	expiresOn := time.Unix(expiresOnUnix, 0)

	// Create azcore.TokenCredential with access token
	cred := accessToken(azcore.AccessToken{
		Token:     accessTokenResp,
		ExpiresOn: expiresOn,
	})

	var _ azcore.TokenCredential = cred

	// var cred azcore.TokenCredential
	// cred, err := azidentity.NewDefaultAzureCredential(nil)

	// if err != nil {
	// 	return nil, fmt.Errorf("failed to obtain a credential: %w", err)
	// }

	return &client{
		credential:   cred,
		vaultClients: make(map[string]*azsecrets.Client),
	}, nil
}

func (c *client) Resolve(ctx context.Context, ref string) (string, error) {
	vault, name, version, err := parseRef(ref)
	if err != nil {
		return "", fmt.Errorf("invalid reference: %w", err)
	}

	if err := c.createClientIfMissing(vault); err != nil {
		return "", fmt.Errorf("failed to create client for vault %q: %w", vault, err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// An empty string version gets the latest version of the secret.
	resp, err := c.vaultClients[vault].GetSecret(ctx, name, version, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %q version %q: %w", name, version, err)
	}

	return *resp.Value, nil
}

func (c *client) Close() error {
	// The client does not need to close its underlying Azure clients.
	// ?(busser): are we sure about this? do any connections need to be closed?
	return nil
}

func (c *client) createClientIfMissing(vault string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.vaultClients[vault] != nil {
		return nil
	}

	vaultURL := fmt.Sprintf("https://%s/", vault)
	azClient, err := azsecrets.NewClient(vaultURL, c.credential, nil)
	if err != nil {
		return fmt.Errorf("client init: %w", err)
	}

	c.vaultClients[vault] = azClient
	return nil
}

func parseRef(ref string) (vaultURL, name, version string, err error) {
	refParts := strings.SplitN(ref, "#", 2)
	if len(refParts) < 1 {
		return "", "", "", errors.New("invalid syntax")
	}
	fullname := refParts[0]
	version = ""
	if len(refParts) == 2 {
		version = refParts[1]
	}

	fullnameParts := strings.SplitN(fullname, "/", 2)
	if len(fullnameParts) < 2 {
		return "", "", "", errors.New("invalid syntax")
	}
	vaultURL = fullnameParts[0]
	name = fullnameParts[1]

	return vaultURL, name, version, nil
}
