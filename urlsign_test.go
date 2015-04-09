package urlsign

import (
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"testing"
)

var signer *Signer

const (
	key = "10e08b48353a7f46513cc4bf619c922eeb6dd8990ce9147875acf59c7504a247190a818168df4e98d32375f074ca2348735cb26904d9ff3db047155966be8bf5"
)

func init() {
	k, err := hex.DecodeString(key)
	if err != nil {
		panic(err)
	}

	signer = &Signer{Key: k, ParamName: "_signature"}
}

func TestURLSigningAndVerification(t *testing.T) {
	u, err := url.Parse("http://example.test/some/path?a=foo&b=bar")
	if err != nil {
		t.Fatal(err)
	}

	signer.SignURL(u)
	if u.Query().Get("_signature") == "" {
		t.Error("expected _signature to be present on signed URL")
	}

	if err := signer.VerifyURL(u); err != nil {
		t.Error("sign/verify signature mismatch")
	}
}

func TestVerifyRequest(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.test/test?a=b", nil)
	if err != nil {
		log.Fatal(err)
	}

	signer.SignURL(req.URL)
	if req.URL.Query().Get("_signature") == "" {
		t.Error("expected _signature to be present on signed URL")
	}

	if err := signer.VerifyReq(req); err != nil {
		t.Error("sign/verify signature mismatch")
	}
}
