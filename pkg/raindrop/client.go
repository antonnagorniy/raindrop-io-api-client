// Package raindrop implements Raindrop.io API client.
//
// API Reference: https://developer.raindrop.io/
package raindrop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"
)

const (
	host                  = "https://api.raindrop.io"
	endpointAuthorize     = "/oauth/authorize"
	endpointTokenExchange = "/oauth/access_token"
	//endpointRefreshToken  = "/oauth/access_token"
	authorizeUrl   = host + endpointAuthorize + "?redirect_uri=%s&client_id=%s"
	defaultTimeout = 5 * time.Second

	// xErrorHeader used to parse error message from Headers on non-2XX responses
	xErrorHeader = "X-Error"
)

// Client is a raindrop client
type Client struct {
	baseURL      *url.URL
	httpClient   *http.Client
	accessToken  string
	ClientId     string
	ClientSecret string
	RedirectUri  string
	clientCode   string
}

type authorizeRequest struct {
	RedirectUri string `json:"redirect_uri"`
	ClientId    string `json:"client_id"`
}

/*type authorizeResponse struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}*/

type accessTokenRequest struct {
	Code         string `json:"code"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectUri  string `json:"redirect_uri"`
	GrantType    string `json:"grant_type"`
}

/*type accessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expires      int    `json:"expires"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
}*/

// Collection represents get collections api response item
type Collection struct {
	ID         uint32 `json:"_id"`
	Color      string `json:"color"`
	Count      uint32 `json:"count"`
	Created    string `json:"created"`
	LastUpdate string `json:"lastUpdate"`
	Expanded   bool   `json:"expanded"`
	Public     bool   `json:"public"`
	Title      string `json:"title"`
	View       string `json:"view"`
}

// Collections represents get collections api response
type Collections struct {
	Result bool         `json:"result"`
	Items  []Collection `json:"items"`
}

// Raindrop represents get raindrops api response item
type Raindrop struct {
	Tags    []string `json:"tags"`
	Cover   string   `json:"cover"`
	Type    string   `json:"type"`
	HTML    string   `json:"html"`
	Excerpt string   `json:"excerpt"`
	Title   string   `json:"title"`
	Link    string   `json:"link"`
}

// Raindrops represents get raindrops api response
type Raindrops struct {
	Result bool       `json:"result"`
	Items  []Raindrop `json:"items"`
}

// Tag represents get tags api response item
type Tag struct {
	ID    string `json:"_id"`
	Count int    `json:"count"`
}

// Tags represents get tags api response
type Tags struct {
	Result bool  `json:"result"`
	Items  []Tag `json:"items"`
}

// NewClient creates Raindrop Client
func NewClient(accessToken string) (*Client, error) {
	if accessToken == "" {
		return nil, errors.New("access token is empty")
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	client := Client{
		baseURL: u,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		accessToken: accessToken,
	}

	return &client, nil
}

// GetCollections call Get root collections API.
// Reference: https://developer.raindrop.io/v1/collections/methods#get-root-collections
func (c *Client) GetCollections() (*Collections, error) {
	uri := "/rest/v1/collections"
	req, err := c.newRequest("GET", uri)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	r := new(Collections)
	if err := parseResponse(response, 200, &r); err != nil {
		return nil, err
	}

	return r, nil
}

// GetRaindrops call Get raindrops API.
// Reference: https://developer.raindrop.io/v1/raindrops/multiple#get-raindrops
func (c *Client) GetRaindrops(collectionID string, perpage int) (*Raindrops, error) {
	uri := fmt.Sprintf("/rest/v1/raindrops/%s", collectionID)
	req, err := c.newRequest("GET", uri)
	if err != nil {
		return nil, err
	}

	query := req.URL.Query()
	query.Add("perpage", fmt.Sprint(perpage))
	req.URL.RawQuery = query.Encode()

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	r := new(Raindrops)
	if err := parseResponse(response, 200, &r); err != nil {
		return nil, err
	}

	return r, nil
}

// GetTags calls Get tags API.
// Reference: https://developer.raindrop.io/v1/tags#get-tags
func (c *Client) GetTags() (*Tags, error) {
	uri := "/rest/v1/tags"
	request, err := c.newRequest("GET", uri)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	r := new(Tags)
	if err := parseResponse(response, 200, &r); err != nil {
		return nil, err
	}

	return r, nil
}

// GetTaggedRaindrops finds raindrops with exact tags.
// This function calls Get raindrops API with collectionID=0 and specify given tag as a search parameter.
//
// Reference: https://developer.raindrop.io/v1/raindrops/multiple#search-parameter
func (c *Client) GetTaggedRaindrops(tag string) (*Raindrops, error) {
	uri := "/rest/v1/raindrops/0"
	request, err := c.newRequest("GET", uri)
	if err != nil {
		return nil, err
	}

	params := request.URL.Query()
	searchParameter := createSingleSearchParameter("tag", tag)
	params.Add("search", searchParameter)
	request.URL.RawQuery = params.Encode()

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	r := new(Raindrops)
	if err := parseResponse(response, 200, &r); err != nil {
		return nil, err
	}

	return r, nil
}

func (c *Client) GetAuthorizationURL() (string, error) {
	return fmt.Sprintf(authorizeUrl, c.RedirectUri, c.ClientId), nil
}

func (c *Client) GetAccessToken(ctx context.Context) (string, error) {

	accessToken := ""
	return accessToken, nil
}

func (c *Client) GetUserCode(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return
	}
	_, err := fmt.Fprintf(w, "<h1>You've been authorized</h1><p>%s</p>", code)
	if err != nil {
		return
	}
	c.clientCode = code
}

func (c *Client) SetAccessToken(accessToken string) {
	c.accessToken = accessToken
}

func createSingleSearchParameter(k, v string) string {
	return fmt.Sprintf(`[{"key":"%s","val":"%s"}]`, k, v)
}

func (c *Client) newRequest(method string, apiPath string) (*http.Request, error) {
	u := *c.baseURL
	u.Path = path.Join(c.baseURL.Path, apiPath)

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}

	bearerToken := fmt.Sprintf("Bearer %s", c.accessToken)
	req.Header.Add("Authorization", bearerToken)

	return req, nil
}

func parseResponse(response *http.Response, expectedStatus int, clazz interface{}) error {
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != expectedStatus {
		return fmt.Errorf("Unexpected Status Code: %d", response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(clazz)
}

func (c *Client) doHTTP(ctx context.Context, httpMethod string, endpoint string, body interface{}) (url.Values, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to marshal input body")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, host+endpoint, bytes.NewBuffer(b))
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to create new request")
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF8")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to send http request")
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Sprintf("API Error: %s", resp.Header.Get(xErrorHeader))
		return url.Values{}, errors.New(err)
	}

	respB, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to read request body")
	}

	values, err := url.ParseQuery(string(respB))
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to parse response body")
	}

	return values, nil
}
