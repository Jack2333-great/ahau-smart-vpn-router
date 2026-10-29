package enlink

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

const api = "/enlink/api/client/"

type Controller struct {
	Base    *url.URL
	HTTP    *http.Client
	TLS     *tls.Config
	Feature string
}
type Response struct {
	Code     json.RawMessage `json:"code"`
	Messages string          `json:"messages"`
	Data     json.RawMessage `json:"data"`
}

func (r Response) OK() bool { return string(r.Code) == `"200"` || string(r.Code) == "200" }
func (r Response) Check() error {
	if !r.OK() {
		// Servers may put arbitrary content in this field. Only bounded numeric
		// codes are useful diagnostics; never reflect response text or tokens.
		code := strings.Trim(string(r.Code), `"`)
		if len(code) == 0 || len(code) > 8 || strings.IndexFunc(code, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
			code = "unsupported"
		}
		return fmt.Errorf("controller returned code %s; authentication/policy must be completed with the official service", code)
	}
	return nil
}
func NewController(base, caFile, feature string) (*Controller, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("server must be an HTTPS origin without credentials/path/query")
	}
	u.Path = ""
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no certificates")
		}
		config.RootCAs = pool
	}
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: config, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, ResponseHeaderTimeout: 10 * time.Second, MaxIdleConnsPerHost: 2}
	h := &http.Client{Transport: transport, Jar: jar, Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return &Controller{Base: u, HTTP: h, TLS: config, Feature: feature}, nil
}

func (c *Controller) Request(ctx context.Context, method, path string, payload any) (Response, error) {
	var result Response
	if !strings.HasPrefix(path, api) {
		return result, errors.New("request outside Enlink client API")
	}
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return result, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base.String()+path, body)
	if err != nil {
		return result, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("featureCode", c.Feature)
	req.Header.Set("model", "Linux "+runtime.GOARCH)
	req.Header.Set("systemInfo", "Linux")
	req.Header.Set("userDeviceName", "campusvpn-router")
	req.Header.Set("terminalInfo", "EnAgent-Linux-research-v0.4")
	req.Header.Set("endevid", "enlink")
	req.Header.Set("Accept-Language", "zh-CN")
	// Old servers use the same cookie string for Authorization. Cookies remain
	// entirely in this process, never in config, argv, logs, or exported reports.
	var cookies []string
	for _, cookie := range c.HTTP.Jar.Cookies(c.Base) {
		cookies = append(cookies, cookie.String())
	}
	if len(cookies) > 0 {
		req.Header.Set("Authorization", strings.Join(cookies, ";"))
	}
	response, err := c.HTTP.Do(req)
	if err != nil {
		return result, errors.New("controller connection failed (check DNS, TLS trust, and network)")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return result, fmt.Errorf("controller HTTP %d; redirects/SSO are not followed automatically", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024+1))
	if err != nil {
		return result, err
	}
	if len(data) > 4*1024*1024 {
		return result, errors.New("controller response too large")
	}
	if err = json.Unmarshal(data, &result); err != nil {
		return result, errors.New("controller did not return expected JSON")
	}
	return result, nil
}

func (c *Controller) GenerateKey(ctx context.Context) (string, error) {
	r, err := c.Request(ctx, "GET", api+"auth/generateKey", nil)
	if err != nil {
		return "", err
	}
	if err = r.Check(); err != nil {
		return "", err
	}
	var key string
	if json.Unmarshal(r.Data, &key) != nil || len(key) != 16 {
		return "", errors.New("unsupported generateKey response (expected v1 ASCII key)")
	}
	return key, nil
}

type Login struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	SID          string `json:"sid"`
	StrategyCode string `json:"strategyCode"`
}

var ErrAuthenticationRejected = errors.New("authentication rejected or requires additional verification")

func (c *Controller) Login(ctx context.Context, username, password string) (Login, error) {
	var login Login
	key, err := c.GenerateKey(ctx)
	if err != nil {
		return login, err
	}
	encrypted, err := EncryptPassword(password, key)
	if err != nil {
		return login, err
	}
	r, err := c.Request(ctx, "POST", api+"auth/login", map[string]string{"username": username, "password": encrypted, "key": key})
	if err != nil {
		return login, err
	}
	if err = r.Check(); err != nil {
		return login, fmt.Errorf("%w: %v", ErrAuthenticationRejected, err)
	}
	if err = json.Unmarshal(r.Data, &login); err != nil {
		return login, errors.New("unsupported login response")
	}
	if login.StrategyCode != "" {
		return login, ErrAuthenticationRejected
	}
	if login.SID == "" || login.ID == "" || login.Username == "" {
		return login, errors.New("incomplete login session")
	}
	return login, nil
}
func (c *Controller) Logout(ctx context.Context, l Login) error {
	r, err := c.Request(ctx, "POST", api+"auth/logout", map[string]string{"username": l.Username, "userId": l.ID})
	if err != nil {
		return err
	}
	return r.Check()
}
func (c *Controller) Ping(ctx context.Context, l Login) error {
	r, err := c.Request(ctx, "GET", api+"service/ping/"+url.PathEscape(l.ID), nil)
	if err != nil {
		return err
	}
	return r.Check()
}
func (c *Controller) Rules(ctx context.Context, l Login) (Rules, error) {
	var rules Rules
	r, err := c.Request(ctx, "GET", api+"user/terminal/rules/"+url.PathEscape(l.ID), nil)
	if err != nil {
		return rules, err
	}
	if err = r.Check(); err != nil {
		return rules, err
	}
	if json.Unmarshal(r.Data, &rules) != nil {
		return rules, errors.New("unsupported rules response")
	}
	return rules, nil
}
func (c *Controller) UpdateIP(ctx context.Context, l Login, ip, gateway string) error {
	r, err := c.Request(ctx, "PUT", api+"user/updateUserSession", map[string]string{"virtualIp": ip, "sessionId": l.SID, "gateway": gateway})
	if err != nil {
		return err
	}
	return r.Check()
}
func (c *Controller) ClearIP(ctx context.Context, l Login) error {
	r, err := c.Request(ctx, "PUT", api+"user/clearVirtualIp", map[string]string{"sessionId": l.SID})
	if err != nil {
		return err
	}
	return r.Check()
}
