package urlsign

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"

	"github.com/divoxx/stackerr"
)

var Log *log.Logger

var (
	ErrOpaqueURL         = stackerr.New("can't sign or verify opaque URL")
	ErrSignatureMismatch = stackerr.New("signature mismatch")
)

type Signer struct {
	Key       []byte
	ParamName string
}

func (s Signer) SignURL(u *url.URL) error {
	if u.Opaque != "" {
		return ErrOpaqueURL
	}

	chunks := []string{u.Scheme, u.Host, u.Path, u.RawQuery}
	if u.User != nil {
		chunks = append(chunks, u.String())
	}

	sig := computeSignature(s.Key, chunks)

	q := u.Query()
	q.Set(s.ParamName, sig)
	u.RawQuery = q.Encode()

	return nil
}

func (s Signer) VerifyURL(u *url.URL) error {
	if u.Opaque != "" {
		return ErrOpaqueURL
	}

	q := u.Query()
	sig := q.Get(s.ParamName)
	q.Del(s.ParamName)

	chunks := []string{u.Scheme, u.Host, u.Path, q.Encode()}
	if u.User != nil {
		chunks = append(chunks, u.String())
	}

	expSig := computeSignature(s.Key, chunks)

	if sig != expSig {
		return ErrSignatureMismatch
	}

	return nil
}

func (s Signer) VerifyReq(req *http.Request) error {
	u := url.URL{Host: req.Host}

	if p := req.Header.Get("X-Forwarded-Proto"); p != "" {
		u.Scheme = p
	} else if req.TLS != nil {
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}

	return s.VerifyURL(u.ResolveReference(req.URL))
}

func computeSignature(key []byte, chunks []string) string {
	h := hmac.New(sha512.New, key)
	for _, c := range chunks {
		h.Write([]byte(c))
	}

	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}
