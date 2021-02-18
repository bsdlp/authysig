package authysig

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/url"
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
	nonce, err := rand.Int(rand.Reader, big.NewInt(1<<31-1))
	if err != nil {
		return err
	}

	return sign(req, parameters, key, nonce.String())
}
