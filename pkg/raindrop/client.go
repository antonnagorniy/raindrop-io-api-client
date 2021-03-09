// Package raindrop implements Raindrop.io API client.
//
// API Reference: https://developer.raindrop.io/
package raindrop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"
)

const (
	apiHost  = "https://api.raindrop.io"
	authHost = "https://raindrop.io"

	endpointAuthorize   = "/oauth/authorize"
	authorizeUri        = endpointAuthorize + "?redirect_uri=%s&client_id=%s"
	endpointAccessToken = "/oauth/access_token"

	endpointGetCollections   = "/rest/v1/collections"
	endpointCreateCollection = "/rest/v1/collection"

	endpointRaindrops = "/rest/v1/raindrops/"
	endpointTags      = "/rest/v1/tags"

	defaultTimeout = 5 * time.Second
)

// Client is a raindrop client
type Client struct {
	apiURL       *url.URL
	authURL      *url.URL
	httpClient   *http.Client
	clientId     string
	clientSecret string
	redirectUri  string
	ClientCode   string
}

// AccessTokenResponse represents the token exchange api response item
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Expires      int    `json:"expires,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Error        string `json:"error,omitempty"`
}

type accessTokenRequest struct {
	Code         string `json:"code"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectUri  string `json:"redirect_uri"`
	GrantType    string `json:"grant_type"`
}

type refreshTokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
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

type createCollectionRequest struct {
	View     string   `json:"view,omitempty"`
	Title    string   `json:"title,omitempty"`
	Sort     int      `json:"sort,omitempty"`
	Public   bool     `json:"public,omitempty"`
	ParentId uint32   `json:"parent.$id,omitempty"`
	Cover    []string `json:"cover,omitempty"`
}

// CreateCollectionResponse represents create collection api response item
type CreateCollectionResponse struct {
	Result       bool                    `json:"result"`
	Item         createCollectionRequest `json:"item,omitempty"`
	Error        string                  `json:"error,omitempty"`
	ErrorMessage string                  `json:"errorMessage,omitempty"`
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

// GetCollections call Get root collections API.
// Reference: https://developer.raindrop.io/v1/collections/methods#get-root-collections
func (c *Client) GetCollections(accessToken string) (*Collections, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointGetCollections)

	req, err := c.newRequest(accessToken, http.MethodGet, u, nil)
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
func (c *Client) GetRaindrops(accessToken string, collectionID string, perpage int) (*Raindrops, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointRaindrops, collectionID)

	req, err := c.newRequest(accessToken, http.MethodGet, u, nil)
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
func (c *Client) GetTags(accessToken string) (*Tags, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointTags)
	request, err := c.newRequest(accessToken, http.MethodGet, u, nil)
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
func (c *Client) GetTaggedRaindrops(accessToken string, tag string) (*Raindrops, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointRaindrops+"0")
	request, err := c.newRequest(accessToken, http.MethodGet, u, nil)
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
func (c *Client) GetAuthorizationURL() (url.URL, error) {
	u := c.authURL
	uri := fmt.Sprintf(authorizeUri, c.redirectUri, c.clientId)
	u.Path = path.Join(uri)
	return *u, nil
}

// GetUserAuthCode returns authorization code
func (c *Client) GetUserAuthCode(authURL url.URL) (string, error) {
	req, err := c.newRequest("", http.MethodGet, authURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Sprintf("user authorization failed: %s", resp.Status)
		return "", errors.New(err)
	}

	respB, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.WithMessage(err, "failed to read request body")
	}

	values, err := url.ParseQuery(string(respB))
	if err != nil {
		return "", errors.WithMessage(err, "failed to parse response body")
	}

	code := values.Get("code")
	authError := values.Get("error")
	if authError != "" {
		return "", errors.New(authError)
	}

	return code, nil
}

// GetAccessToken exchanges user's authorization code to access token
// Reference: https://developer.raindrop.io/v1/authentication/token#step-3-the-token-exchange
func (c *Client) GetAccessToken(userCode string) (*AccessTokenResponse, error) {
	fullUrl := *c.authURL
	fullUrl.Path = path.Join(endpointAccessToken)

	body := accessTokenRequest{
		Code:         userCode,
		ClientID:     c.clientId,
		ClientSecret: c.clientSecret,
		RedirectUri:  c.redirectUri,
		GrantType:    "authorization_code",
	}

	request, err := c.newRequest("", http.MethodPost, fullUrl, body)
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
// Reference: https://developer.raindrop.io/v1/authentication/token#the-access-token-refresh
func (c *Client) RefreshAccessToken(refreshToken string) (*AccessTokenResponse, error) {
	fullUrl := *c.authURL
	fullUrl.Path = path.Join(endpointAccessToken)

	body := refreshTokenRequest{
		ClientId:     c.clientId,
		ClientSecret: c.clientSecret,
		GrantType:    "authorization_code",
		RefreshToken: refreshToken,
	}

	request, err := c.newRequest("", http.MethodPost, fullUrl, body)
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

// CreateCollection creates new Collection
// Reference: https://developer.raindrop.io/v1/collections/methods#create-collection
func (c *Client) CreateCollection(accessToken string, view string, title string, sort int,
	public bool, parentId uint32, cover []string) (*CreateCollectionResponse, error) {

	fullUrl := *c.apiURL
	fullUrl.Path = path.Join(endpointCreateCollection)

	var collection createCollectionRequest

	if parentId == 0 {
		collection = createCollectionRequest{
			View:   view,
			Title:  title,
			Sort:   sort,
			Public: public,
			Cover:  cover,
		}
	} else {
		collection = createCollectionRequest{
			View:     view,
			Title:    title,
			Sort:     sort,
			Public:   public,
			ParentId: parentId,
			Cover:    cover,
		}
	}

	request, err := c.newRequest(accessToken, http.MethodPost, fullUrl, collection)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	result := new(CreateCollectionResponse)
	err = parseResponse(response, 200, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) GetAuthorizationCodeHandler(w http.ResponseWriter, r *http.Request) {
	code, err := c.GetAuthorizationCode(r)
	if err != nil {
		fmt.Println(err)
	}

	_, err = fmt.Fprintf(w, "<h1>You've been authorized</h1><p>%s</p>", code)
	if err != nil {
		fmt.Println(err)
	}
	c.ClientCode = code
}

func (c *Client) GetAuthorizationCode(r *http.Request) (string, error) {
	code := r.URL.Query().Get("code")
	authErr := r.URL.Query().Get("error")
	if code == "" && authErr != "" {
		return "", errors.New("Can't get authorization code: " + authErr)
	} else if code == "" {
		return "", errors.New("Can't get authorization code: " + strconv.Itoa(r.Response.StatusCode))
	}

	return code, nil
}

func createSingleSearchParameter(k, v string) string {
	return fmt.Sprintf(`[{"key":"%s","val":"%s"}]`, k, v)
}

func (c *Client) newRequest(accessToken string, httpMethod string, fullUrl url.URL,
	body interface{}) (*http.Request, error) {

	u, err := url.QueryUnescape(fullUrl.String())
	if err != nil {
		return nil, err
	}

	var b []byte = nil
	if body != nil {
		b, err = json.Marshal(body)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to marshal input body")
		}
	}

	req, err := http.NewRequest(httpMethod, u, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")

	if accessToken != "" {
		bearerToken := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Add("Authorization", bearerToken)
	}

	return req, nil
}

func parseResponse(response *http.Response, expectedStatus int, clazz interface{}) error {
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != expectedStatus && response.StatusCode != 400 {
		err := fmt.Errorf("unexpected Status Code: %d", response.StatusCode)
		fmt.Printf("Can't parse response" + err.Error())
		return err
	}

	return json.NewDecoder(response.Body).Decode(clazz)
}
