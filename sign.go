package authysig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func sign(req *http.Request, key []byte, nonce string) error {
	var data strings.Builder
	_, err := data.WriteString(nonce)
	if err != nil {
		return err
	}

	_, err = data.WriteString("|")
	if err != nil {
		return err
	}

	_, err = data.WriteString(req.Method)
	if err != nil {
		return err
	}

	_, err = data.WriteString("|")
	if err != nil {
		return err
	}

	u := *req.URL
	query := u.Query()
	u.RawQuery = ""
	_, err = data.WriteString(u.String())
	if err != nil {
		return err
	}

	_, err = data.WriteString("|")
	if err != nil {
		return err
	}

	_, err = data.WriteString(query.Encode())
	if err != nil {
		return err
	}

	digest := hmac.New(sha256.New, key).Sum([]byte(data.String()))
	req.Header.Set("X-Authy-Signature", base64.StdEncoding.EncodeToString(digest))
	req.Header.Set("X-Authy-Signature-Nonce", nonce)

	return nil
}

func Sign(req *http.Request, key []byte) error {
	nonce := strconv.FormatInt(time.Now().UnixNano(), 10)
	return sign(req, key, nonce)
}
