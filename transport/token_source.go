/*
Copyright 2021 The Kubernetes Authors.

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
	sync
	time

	golang.org/x/oauth2
)

// NewCachedTokenSource returns a TokenSource that caches the token returned by the wrapped TokenSource.
// It will return the cached token if it is not expired.
func NewCachedTokenSource(source oauth2.TokenSource) oauth2.TokenSource {
	return &cachedTokenSource{
		source: source,
	}
}

type cachedTokenSource struct {
	lk          sync.Mutex
	source      oauth2.TokenSource
	cachedToken *oauth2.Token
}

func (c *cachedTokenSource) Token() (*oauth2.Token, error) {
	c.lk.Lock()
	defer c.lk.Unlock()
	if c.cachedToken != nil && c.cachedToken.Expiry.After(time.Now()) {
		return c.cachedToken, nil
	}
	token, err := c.source.Token()
	if err != nil {
		return nil, err
	}
	c.cachedToken = token
	return token, nil
}

func (c *cachedTokenSource) Invalidate() {
	c.lk.Lock()
	defer c.lk.Unlock()
	c.cachedToken = nil
}
