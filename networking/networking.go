package networking

import (
	"bytes"
	"net/http"

	"github.com/juju/errors"
)

// SendSoap send soap message
func SendSoap(httpClient *http.Client, endpoint, message string) (*http.Response, error) {
	resp, err := httpClient.Post(endpoint, "application/soap+xml; charset=utf-8", bytes.NewBufferString(message))
	if err != nil {
		return resp, errors.Annotate(err, "Post")
	}

	return resp, nil
}

// SendSoapWithHeaders send soap message with custom headers
func SendSoapWithHeaders(httpClient *http.Client, endpoint, message string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(message))
	if err != nil {
		return nil, errors.Annotate(err, "NewRequest")
	}

	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return resp, errors.Annotate(err, "Do")
	}

	return resp, nil
}
