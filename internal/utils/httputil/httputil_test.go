package httputil

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestBuildProxyURLPreservesCredentialsAndIPv6(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "[::1]"} {
		raw := BuildProxyURL("http", host, "7890", "user@company", "p@ss:/?#%")
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		password, _ := parsed.User.Password()
		if parsed.User.Username() != "user@company" || password != "p@ss:/?#%" {
			t.Fatal("proxy credentials changed during URL construction")
		}
		if parsed.Port() != "7890" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			t.Fatal("proxy credentials leaked into URL components")
		}
	}
}

func TestCreateHTTPClientHonorsInsecureTLSVerifyEnv(t *testing.T) {
	t.Setenv(InsecureSkipTLSVerifyEnv, "true")

	client, err := CreateHTTPClient("", time.Second)
	if err != nil {
		t.Fatalf("CreateHTTPClient returned error: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatalf("TLSClientConfig is nil")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected InsecureSkipVerify to be true")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2 minimum, got %d", transport.TLSClientConfig.MinVersion)
	}
}

func TestCreateHTTPClientKeepsTLSVerificationByDefault(t *testing.T) {
	t.Setenv(InsecureSkipTLSVerifyEnv, "")

	client, err := CreateHTTPClient("", time.Second)
	if err != nil {
		t.Fatalf("CreateHTTPClient returned error: %v", err)
	}

	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected InsecureSkipVerify to be false by default")
	}
}

func TestCreateHTTPClientNegotiatesHTTP2(t *testing.T) {
	t.Setenv(InsecureSkipTLSVerifyEnv, "true")

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("expected HTTP/2 request, got %s", r.Proto)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	client, err := CreateHTTPClient("", 5*time.Second)
	if err != nil {
		t.Fatalf("CreateHTTPClient returned error: %v", err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("HTTP/2 request failed: %v", err)
	}
	defer response.Body.Close()
}

func TestCreateHTTPClientFallsBackToHTTP1(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Errorf("expected HTTP/1.1 request, got %s", r.Proto)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	client, err := CreateHTTPClient("", 5*time.Second)
	if err != nil {
		t.Fatalf("CreateHTTPClient returned error: %v", err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("HTTP/1.1 request failed: %v", err)
	}
	defer response.Body.Close()
}

type fakeSettings struct {
	settings  map[string]string
	encrypted map[string]string
}

func (f fakeSettings) GetSetting(key string) (string, error) {
	return f.settings[key], nil
}

func (f fakeSettings) GetEncryptedSetting(key string) (string, error) {
	return f.encrypted[key], nil
}

func TestCreateHTTPClientWithProxySettingsAppliesGlobalProxy(t *testing.T) {
	settings := fakeSettings{
		settings: map[string]string{
			"proxy_enabled": "true",
			"proxy_type":    "http",
			"proxy_host":    "127.0.0.1",
			"proxy_port":    "8080",
		},
		encrypted: map[string]string{
			"proxy_username": "user",
			"proxy_password": "pass",
		},
	}

	client, err := CreateHTTPClientWithProxySettings(settings, time.Second)
	if err != nil {
		t.Fatalf("CreateHTTPClientWithProxySettings error: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type: %T", client.Transport)
	}
	if transport.Proxy == nil {
		t.Fatalf("expected proxy function")
	}

	proxyURL, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}})
	if err != nil {
		t.Fatalf("proxy function error: %v", err)
	}
	if proxyURL == nil || proxyURL.String() != "http://user:pass@127.0.0.1:8080" {
		t.Fatalf("unexpected proxy URL: %v", proxyURL)
	}
}

func TestCreateHTTPClientWithProxySettingsSkipsProxyWhenDisabled(t *testing.T) {
	settings := fakeSettings{
		settings: map[string]string{
			"proxy_enabled": "false",
		},
		encrypted: map[string]string{},
	}

	client, err := CreateHTTPClientWithProxySettings(settings, time.Second)
	if err != nil {
		t.Fatalf("CreateHTTPClientWithProxySettings error: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type: %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatalf("expected no proxy function when global proxy is disabled")
	}
}
