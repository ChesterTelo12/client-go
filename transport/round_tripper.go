/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package transport

import ( 
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// HTTPWrappersForConfig wraps a round tripper with the standard wrappers.
func HTTPWrappersForConfig(config *Config, rt http.RoundTripper) (http.RoundTripper, error) {
	if config.WrapTransport != nil {
		rt = config.WrapTransport(rt)
	}
	if config.HasBasicAuth() && config.HasTokenAuth() {
		return nil, fmt.Errorf("username/password or bearer token may be set, but not both")
	}
	if config.HasTokenAuth() && config.WrapTransport == nil {
		if config.TokenSource != nil {
			rt = NewTokenSourceWrapTransport(config.TokenSource, rt)
		} else if len(config.BearerToken) > 0 {
			rt = NewBearerAuthRoundTripper(config.BearerToken, rt)
		}
	}
	if config.HasBasicAuth() {
		rt = NewBasicAuthRoundTripper(config.Username, config.Password, rt)
	}
	return rt, nil
}

// NewTokenSourceWrapTransport returns a RoundTripper that injects bearer tokens from the source.
func NewTokenSourceWrapTransport(ts oauth2.TokenSource, rt http.RoundTripper) http.RoundTripper {
	return &tokenSourceWrap{
		base: rt,
		ts:   ts,
	}
}

type tokenInvalidator interface {
	Invalidate()
}

type tokenSourceWrap struct {
	base http.RoundTripper
	ts   oauth2.TokenSource
}

func (t *tokenSourceWrap) RoundTrip(req *http.Request) (*http.Response, error) {
	auth := req.Header.Get("Authorization")
	if len(auth) != 0 && !strings.HasPrefix(auth, "Bearer ") {
		return t.base.RoundTrip(req)
	}

	token, err := t.ts.Token()
	if err != nil {
		return nil, err
	}

	reqToken := ""
	if strings.HasPrefix(auth, "Bearer ") {
		reqToken = strings.TrimPrefix(auth, "Bearer ")
	}

	if reqToken != token.AccessToken {
		req = cloneRequest(req)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	}

	resp, err := t.base.RoundTrip(req)
	if err == nil && resp != nil && resp.StatusCode == http.StatusUnauthorized {
		if invalidator, ok := t.ts.(tokenInvalidator); ok {
			invalidator.Invalidate()
		}
	}
	return resp, err
}

// NewBasicAuthRoundTripper returns a RoundTripper that injects basic auth credentials.
func NewBasicAuthRoundTripper(username, password string, rt http.RoundTripper) http.RoundTripper {
	return &basicAuthRoundTripper{
		username: username,
		password: password,
		rt:       rt,
	}
}

type basicAuthRoundTripper struct {
	username string
	password string
	rt       http.RoundTripper
}

func (rt *basicAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get("Authorization")) != 0 {
		return rt.rt.RoundTrip(req)
	}
	req = cloneRequest(req)
	req.SetBasicAuth(rt.username, rt.password)
	return rt.rt.RoundTrip(req)
}

// NewBearerAuthRoundTripper returns a RoundTripper that injects bearer tokens.
func NewBearerAuthRoundTripper(token string, rt http.RoundTripper) http.RoundTripper {
	return &bearerAuthRoundTripper{
		token: token,
		rt:    rt,
	}
}

type bearerAuthRoundTripper struct {
	token string
	rt    http.RoundTripper
}

func (rt *bearerAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get("Authorization")) != 0 {
		return rt.rt.RoundTrip(req)
	}
	req = cloneRequest(req)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", rt.token))
	return rt.rt.RoundTrip(req)
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(req *http.Request) *http.Request {
	r := new(http.Request)
	*r = *req
	r.Header = make(http.Header, len(req.Header))
	for k, s := range req.Header {
		r.Header[k] = append([]string(nil), s...)
	}
	return r
}
