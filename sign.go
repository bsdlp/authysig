package authysig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func sign(req *http.Request, parameters url.Values, key []byte, nonce string) error {
	mac := hmac.New(sha256.New, key)
	_, err := io.WriteString(mac, nonce)
	if err != nil {
		return err
	}

	_, err = io.WriteString(mac, "|")
	if err != nil {
		return err
	}

	_, err = io.WriteString(mac, req.Method)
	if err != nil {
		return err
	}

	_, err = io.WriteString(mac, "|")
	if err != nil {
		return err
	}

	u := *req.URL
	u.RawQuery = ""
	_, err = io.WriteString(mac, u.String())
	if err != nil {
		return err
	}

	_, err = io.WriteString(mac, "|")
	if err != nil {
		return err
	}

	_, err = io.WriteString(mac, parameters.Encode())
	if err != nil {
		return err
	}

	digest := mac.Sum(nil)
	req.Header.Set("X-Authy-Signature", base64.StdEncoding.EncodeToString(digest))
	req.Header.Set("X-Authy-Signature-Nonce", nonce)

	return nil
}

func Sign(req *http.Request, parameters url.Values, key []byte) error {
	nonce := strconv.FormatInt(time.Now().UnixNano(), 10)
	return sign(req, parameters, key, nonce)
}
