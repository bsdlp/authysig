package authysig

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
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

	err = Sign(req, keys, []byte(authyApiSigningKey))
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

	payload := url.Values{}
	payload.Set("app_api_key", authyAppApiKey)
	payload.Set("access_key", authyAccessKey)
	hookName := "testhook" + strconv.FormatInt(time.Now().Unix(), 10)
	payload.Set("name", hookName)
	payload.Set("url", "http://localhost:6969/callback")
	payload.Add("events[]", "user_account_deleted")
	payload.Add("events[]", "device_registration_completed")
	unescapedPayload, err := url.QueryUnescape(payload.Encode())
	if err != nil {
		t.Errorf("error unescaping create request: %s", err)
	}
	req, err = http.NewRequest("POST", "https://api.authy.com/dashboard/json/application/webhooks", strings.NewReader(unescapedPayload))
	if err != nil {
		t.Errorf("error creating create request: %s", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	err = Sign(req, payload, []byte(authyApiSigningKey))
	if err != nil {
		t.Errorf("error signing create request: %s", err)
	}

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("error sending create request: %s", err)
	}

	type createResponse struct {
		Webhook struct {
			Id         string `json:"id"`
			SigningKey string `json:"signing_key"`
		} `json:"webhook"`
		Message string `json:"message"`
		Success bool   `json:"success"`
	}
	var createResponseData createResponse
	err = json.NewDecoder(resp.Body).Decode(&createResponseData)
	if err != nil {
		t.Errorf("error decoding create response: %s", err)
	}

	if !createResponseData.Success {
		t.Errorf("create failed: %s", createResponseData.Message)
	}

	payload = url.Values{}
	payload.Set("app_api_key", authyAppApiKey)
	payload.Set("access_key", authyAccessKey)
	req, err = http.NewRequest("DELETE", fmt.Sprintf("https://api.authy.com/dashboard/json/application/webhooks/%s", createResponseData.Webhook.Id), strings.NewReader(payload.Encode()))
	if err != nil {
		t.Errorf("error creating delete request: %s", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	err = Sign(req, keys, []byte(authyApiSigningKey))
	if err != nil {
		t.Errorf("error signing delete request: %s", err)
	}

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("error sending delete request: %s", err)
	}

	type deleteResponse struct {
		Message string `json:"message"`
		Success bool   `json:"success"`
	}
	var deleteResponseData deleteResponse
	err = json.NewDecoder(resp.Body).Decode(&deleteResponseData)
	if err != nil {
		t.Errorf("error decoding delete response: %s", err)
	}

	if !deleteResponseData.Success {
		t.Errorf("delete failed: %s", deleteResponseData.Message)
	}
}
