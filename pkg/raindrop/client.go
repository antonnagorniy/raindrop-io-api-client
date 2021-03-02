// Package raindrop implements Raindrop.io API client.
//
// API Reference: https://developer.raindrop.io/
package raindrop

import (
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
	apiHost             = "https://api.raindrop.io"
	authHost            = "https://raindrop.io"
	endpointAuthorize   = "/oauth/authorize"
	endpointAccessToken = "/oauth/access_token"
	authorizeUri        = endpointAuthorize + "?redirect_uri=%s&client_id=%s"
	accessTokenUri      = endpointAccessToken + "?code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=%s"
	refreshTokenUri     = endpointAccessToken + "?client_id=%s&client_secret=%s&grant_type=%s&refresh_token=%s"
	defaultTimeout      = 5 * time.Second
)

// Client is a raindrop client
type Client struct {
	apiURL       *url.URL
	authURL      *url.URL
	httpClient   *http.Client
	accessToken  string
	clientId     string
	clientSecret string
	redirectUri  string
	clientCode   string
	refreshToken string
}

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Expires      int    `json:"expires,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Error        string `json:"error,omitempty"`
}

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
func NewClient(clientId string, clientSecret string, redirectUri string) (*Client, error) {
	auth, err := url.Parse(authHost)
	if err != nil {
		return nil, err
	}
	api, err := url.Parse(apiHost)
	if err != nil {
		return nil, err
	}

	client := Client{
		apiURL:  api,
		authURL: auth,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		clientId:     clientId,
		clientSecret: clientSecret,
		redirectUri:  redirectUri,
	}

	return &client, nil
}

func (c *Client) SetAccessToken(accessToken string) {
	c.accessToken = accessToken
}

// GetCollections call Get root collections API.
// Reference: https://developer.raindrop.io/v1/collections/methods#get-root-collections
func (c *Client) GetCollections() (*Collections, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, "/rest/v1/collections")

	req, err := c.newRequest("GET", u)
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
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, "/rest/v1/raindrops/", collectionID)

	req, err := c.newRequest("GET", u)
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
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, "/rest/v1/tags")
	request, err := c.newRequest("GET", u)
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
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, "/rest/v1/raindrops/0")
	request, err := c.newRequest("GET", u)
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

// GetAuthorizationURL returns URL for user to authorize app
func (c *Client) GetAuthorizationURL() (string, error) {
	u := c.authURL
	uri := fmt.Sprintf(authorizeUri, c.redirectUri, c.clientId)
	u.Path = path.Join(uri)
	return url.QueryUnescape(u.String())
}

// GetAccessToken exchanges user's authorization code to access token
func (c *Client) GetAccessToken() (*AccessTokenResponse, error) {
	fullUrl := c.getTokenUrl(false)

	request, err := c.newRequest(http.MethodPost, fullUrl)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	result := new(AccessTokenResponse)
	err = parseResponse(response, 200, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// RefreshAccessToken refreshes expired token
func (c *Client) RefreshAccessToken() error {
	fullUrl := c.getTokenUrl(true)

	request, err := c.newRequest(http.MethodPost, fullUrl)
	if err != nil {
		return err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	result := new(AccessTokenResponse)
	err = parseResponse(response, 200, &result)
	if err != nil {
		return err
	}

	c.accessToken = result.AccessToken
	c.refreshToken = result.RefreshToken
	return nil
}

func (c *Client) GetUserCodeHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return
	}
	_, err := fmt.Fprintf(w, "<h1>You've been authorized</h1><p>%s</p>", code)
	if err != nil {
		return
	}
	c.clientCode = code
	fmt.Println(c.clientCode)
}

func (c *Client) GetCode() string {
	return c.clientCode
}

func (c *Client) getTokenUrl(isRefresh bool) url.URL {
	u := *c.authURL
	if isRefresh {
		refresh := fmt.Sprintf(refreshTokenUri, c.clientId, c.clientSecret, "refresh_token", c.refreshToken)
		u.Path = path.Join(refresh)

	}
	access := fmt.Sprintf(accessTokenUri, c.clientCode, c.clientId, c.clientSecret, c.redirectUri, "authorization_code")
	u.Path = path.Join(access)
	testUrl, _ := url.QueryUnescape(u.String())
	fmt.Printf("Get access token URL: %s\n", testUrl)
	return u
}

func createSingleSearchParameter(k, v string) string {
	return fmt.Sprintf(`[{"key":"%s","val":"%s"}]`, k, v)
}

func (c *Client) newRequest(httpMethod string, fullUrl url.URL) (*http.Request, error) {
	req, err := http.NewRequest(httpMethod, fullUrl.String(), nil)
	if err != nil {
		return nil, err
	}

	if c.accessToken != "" {
		bearerToken := fmt.Sprintf("Bearer %s", c.accessToken)
		req.Header.Add("Authorization", bearerToken)
	}

	return req, nil
}

func parseResponse(response *http.Response, expectedStatus int, clazz interface{}) error {
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != expectedStatus {
		return fmt.Errorf("unexpected Status Code: %d", response.StatusCode)
	}

	return json.NewDecoder(response.Body).Decode(clazz)
}

func (c *Client) doCodeReq(httpMethod string, endpoint string) (url.Values, error) {
	req, err := http.NewRequest(httpMethod, endpoint, nil)
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to create new request")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return url.Values{}, errors.WithMessage(err, "failed to send http request")
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Sprint("API Error")
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
