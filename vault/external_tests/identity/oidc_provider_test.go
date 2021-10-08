package identity

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/require"
)

func TestOIDC_Path_OIDC_Client_Validation(t *testing.T) {
	logger := logging.NewVaultLogger(hclog.Trace)
	coreConfig := &vault.CoreConfig{
		Logger:   logger,
		EnableUI: true,
	}
	clusterOptions := &vault.TestClusterOptions{
		NumCores:    1,
		HandlerFunc: vaulthttp.Handler,
	}
	cluster := vault.NewTestCluster(t, coreConfig, clusterOptions)
	cluster.Start()
	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client

	// Create a key
	_, err := client.Logical().Write("identity/oidc/key/test-key", map[string]interface{}{
		"allowed_client_ids": []string{"*"},
		"algorithm":          "RS256",
	})
	require.NoError(t, err)

	// Create an entity
	resp, err := client.Logical().Write("identity/entity", map[string]interface{}{
		"name": "test-entity",
		"metadata": map[string]string{
			"email":        "test@hashicorp.com",
			"phone_number": "123-456-7890",
		},
	})
	require.NoError(t, err)
	entityID := resp.Data["id"].(string)

	// Create an assignment
	_, err = client.Logical().Write("identity/oidc/assignment/test-assignment", map[string]interface{}{
		"entity_ids": []string{entityID},
	})
	require.NoError(t, err)

	// Create a client
	_, err = client.Logical().Write("identity/oidc/client/test-client", map[string]interface{}{
		"key":              "test-key",
		"redirect_uris":    []string{"https://127.0.0.1:8251/callback"},
		"assignments":      []string{"test-assignment"},
		"id_token_ttl":     "24h",
		"access_token_ttl": "24h",
	})
	require.NoError(t, err)

	// Read client ID and secret
	resp, err = client.Logical().Read("identity/oidc/client/test-client")
	require.NoError(t, err)
	clientID := resp.Data["client_id"].(string)
	clientSecret := resp.Data["client_secret"].(string)

	// Create the provider
	_, err = client.Logical().Write("identity/oidc/provider/test-provider", map[string]interface{}{
		"allowed_client_ids": []string{clientID},
	})
	require.NoError(t, err)

	// Read the issuer from the discovery document
	r, err := client.RawRequest(client.NewRequest(http.MethodGet,
		"/v1/identity/oidc/provider/test-provider/.well-known/openid-configuration"))
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, http.StatusOK, r.StatusCode)
	defer r.Body.Close()
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&discovery))

	// Configure the OIDC client
	pc, err := oidc.NewConfig(discovery.Issuer,
		clientID, oidc.ClientSecret(clientSecret),
		[]oidc.Alg{oidc.RS256},
		[]string{"http://127.0.0.1:8251/callback"},
		oidc.WithProviderCA(string(cluster.CACertPEM)))
	require.NoError(t, err)

	p, err := oidc.NewProvider(pc)
	require.NoError(t, err)
	defer p.Done()

	// TODO: authenticate and get the auth code via client.SetToken("foo") + /authorize
}

func setupOIDCTestCluster(t *testing.T, numCores int) (*vault.TestCluster, *api.Client) {
	logger := logging.NewVaultLogger(hclog.Trace)
	coreConfig := &vault.CoreConfig{
		Logger: logger,
	}
	clusterOptions := &vault.TestClusterOptions{
		NumCores:    numCores,
		HandlerFunc: vaulthttp.Handler,
	}
	cluster := vault.NewTestCluster(t, coreConfig, clusterOptions)
	cluster.Start()
	vault.TestWaitActive(t, cluster.Cores[0].Core)

	return cluster, cluster.Cores[0].Client
}
