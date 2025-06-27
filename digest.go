package onvif

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
)

const (
	// DefaultAlgorithm is the default hashing algorithm for digest authentication
	DefaultAlgorithm = "MD5"
	// DefaultNC is the default nonce count value
	DefaultNC = "00000001"
	// CnonceLength is the length of the client nonce in bytes
	CnonceLength = 8
)

var (
	// ErrInvalidDigestHeader indicates that the WWW-Authenticate header is invalid
	ErrInvalidDigestHeader = errors.New("invalid digest authentication header")
)

// DigestParams represents the parameters from a WWW-Authenticate digest header
type DigestParams struct {
	Realm     string
	Nonce     string
	QOP       string
	Opaque    string
	Algorithm string
}

// AuthRequest represents the authentication request parameters
type AuthRequest struct {
	Username string
	Password string
	Method   string
	URI      string
}

// GetDigestAuthHeader generates a digest authentication header
// from the WWW-Authenticate header, username, password, HTTP method, and URI.
// It returns the digest header string or an error if parsing fails.
func GetDigestAuthHeader(wwwAuthHeader string, username, password, method, uri string) (string, error) {
	digestParams, err := parseDigestAuthParams(wwwAuthHeader)
	if err != nil {
		return "", err
	}

	authReq := AuthRequest{
		Username: username,
		Password: password,
		Method:   method,
		URI:      uri,
	}

	digestHeader := buildDigestAuthHeader(authReq, digestParams)
	return digestHeader, nil
}

// parseDigestAuthParams parses the WWW-Authenticate header for digest auth
func parseDigestAuthParams(header string) (*DigestParams, error) {
	if !strings.HasPrefix(header, "Digest ") {
		return nil, ErrInvalidDigestHeader
	}

	header = strings.TrimPrefix(header, "Digest ")
	params := make(map[string]string)

	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = strings.Trim(kv[1], `"`)
		}
	}

	// Check for required parameters
	if params["realm"] == "" || params["nonce"] == "" {
		return nil, ErrInvalidDigestHeader
	}

	algorithm := params["algorithm"]
	if algorithm == "" {
		algorithm = DefaultAlgorithm
	}

	return &DigestParams{
		Realm:     params["realm"],
		Nonce:     params["nonce"],
		QOP:       params["qop"],
		Opaque:    params["opaque"],
		Algorithm: algorithm,
	}, nil
}

// buildDigestAuthHeader builds the digest auth header value
func buildDigestAuthHeader(authReq AuthRequest, params *DigestParams) string {
	ha1 := computeHA1(authReq.Username, authReq.Password, params.Realm, params.Algorithm)
	ha2 := computeHA2(authReq.Method, authReq.URI)

	cnonce := generateCnonce()
	nc := DefaultNC

	response := computeResponse(ha1, ha2, params.Nonce, params.QOP, nc, cnonce)

	return formatDigestHeader(authReq.Username, authReq.URI, params, response, nc, cnonce)
}

// computeHA1 calculates the HA1 hash according to RFC 2617
func computeHA1(username, password, realm, algorithm string) string {
	data := username + ":" + realm + ":" + password
	return md5Hash(data)
}

// computeHA2 calculates the HA2 hash according to RFC 2617
func computeHA2(method, uri string) string {
	data := method + ":" + uri
	return md5Hash(data)
}

// computeResponse calculates the response hash according to RFC 2617
func computeResponse(ha1, ha2, nonce, qop, nc, cnonce string) string {
	if qop != "" {
		return md5Hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	}
	return md5Hash(ha1 + ":" + nonce + ":" + ha2)
}

// formatDigestHeader formats the digest authentication header
func formatDigestHeader(username, uri string, params *DigestParams, response, nc, cnonce string) string {
	header := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, params.Realm, params.Nonce, uri, response)

	if params.Opaque != "" {
		header += fmt.Sprintf(`, opaque="%s"`, params.Opaque)
	}

	if params.Algorithm != "" {
		header += fmt.Sprintf(`, algorithm="%s"`, params.Algorithm)
	}

	if params.QOP != "" {
		header += fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, params.QOP, nc, cnonce)
	}

	return header
}

// md5Hash computes the MD5 hash of the given data and returns it as a hex string
func md5Hash(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// generateCnonce generates a random client nonce for digest authentication
func generateCnonce() string {
	b := make([]byte, CnonceLength)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
