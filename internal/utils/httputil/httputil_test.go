package httputil

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"
	"time"
)

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

func TestBuildGlobalProxyURL(t *testing.T) {
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

	proxyURL := BuildGlobalProxyURL(settings)
	if proxyURL != "http://user:pass@127.0.0.1:8080" {
		t.Fatalf("unexpected proxy URL: %s", proxyURL)
	}

	settings.settings["proxy_enabled"] = "false"
	if proxyURL := BuildGlobalProxyURL(settings); proxyURL != "" {
		t.Fatalf("expected empty proxy URL when disabled, got %s", proxyURL)
	}
}

func TestCreateHTTPClientFromSettings(t *testing.T) {
	settings := fakeSettings{
		settings: map[string]string{
			"proxy_enabled": "true",
			"proxy_type":    "http",
			"proxy_host":    "127.0.0.1",
			"proxy_port":    "8080",
		},
		encrypted: map[string]string{},
	}

	client, err := CreateHTTPClientFromSettings(settings, time.Second)
	if err != nil {
		t.Fatalf("CreateHTTPClientFromSettings error: %v", err)
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
	if proxyURL == nil || proxyURL.String() != "http://127.0.0.1:8080" {
		t.Fatalf("unexpected proxy URL: %v", proxyURL)
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
