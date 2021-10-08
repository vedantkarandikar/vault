package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/util"
	"github.com/hashicorp/go-hclog"
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
	//       remove dependence on UI and callback here

	// Create the OIDC request state
	oidcRequest, err := oidc.NewRequest(10*time.Minute,
		"http://127.0.0.1:8251/callback",
		oidc.WithScopes("openid"))
	require.NoError(t, err)

	// Generate the auth URL to open in the browser
	authURL, err := p.AuthURL(context.Background(), oidcRequest)
	require.NoError(t, err)

	errorCh := make(chan error)
	doneCh := make(chan struct{})
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	// Create the HTTP handler to handle the browser redirect and finish the flow
	http.HandleFunc("/callback", func(w http.ResponseWriter, req *http.Request) {
		// Obtain the authorization code and state
		code := req.FormValue("code")
		state := req.FormValue("state")
		require.Equal(t, oidcRequest.State(), state)

		// Exchange the authorization code for an ID token and access token
		token, err := p.Exchange(context.Background(), oidcRequest, state, code)
		require.NoError(t, err)
		idToken := token.IDToken()

		// Get the ID token claims
		var allClaims map[string]interface{}
		require.NoError(t, idToken.Claims(&allClaims))
		delete(allClaims, "nonce")

		// Get the sub claim for userinfo validation
		var subject string
		if sub, ok := allClaims["sub"].(string); ok {
			subject = sub
		}

		// Request userinfo using the access token
		err = p.UserInfo(context.Background(), token.StaticTokenSource(), subject, &allClaims)
		require.NoError(t, err)

		claims, err := json.MarshalIndent(allClaims, "", "  ")
		require.NoError(t, err)

		t.Log(string(claims))
		_, err = io.WriteString(w, "\n")
		require.NoError(t, err)

		close(doneCh)
	})

	// Serve the redirect handler
	go func() {
		errorCh <- http.ListenAndServe("127.0.0.1:8251", nil)
	}()

	// Open the auth URL in the browser
	err = util.OpenURL(authURL)
	if err != nil {
		log.Fatal(err)
	}

	// Block until signal, error, or done
	select {
	case sig := <-signalCh:
		fmt.Printf("received signal: %v\n", sig)
		os.Exit(0)
	case err := <-errorCh:
		log.Fatal(err)
	case <-doneCh:
		os.Exit(0)
	}
}
