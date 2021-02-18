package authysig

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestIntegrationSign(t *testing.T) {
	authyAccessKey := os.Getenv("AUTHY_ACCESS_KEY")
	authyApiSigningKey := os.Getenv("AUTHY_API_SIGNING_KEY")
	authyAppApiKey := os.Getenv("AUTHY_APP_API_KEY")

	keys := url.Values{}
	keys.Set("app_api_key", authyAppApiKey)
	keys.Set("access_key", authyAccessKey)
	req, err := http.NewRequest("GET", "https://api.authy.com/dashboard/json/application/webhooks", strings.NewReader(keys.Encode()))
	if err != nil {
		t.Errorf("error creating list request: %s", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	err = Sign(req, []byte(authyApiSigningKey))
	if err != nil {
		t.Errorf("error signing list request: %s", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("error sending list request: %s", err)
	}

	type listResponse struct {
		Success bool `json:"success"`
	}
	var listResponseData listResponse
	err = json.NewDecoder(resp.Body).Decode(&listResponseData)
	if err != nil {
		t.Errorf("error decoding list response: %s", err)
	}

	if !listResponseData.Success {
		t.Error("list failed")
	}
}
