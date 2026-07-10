package models

import "testing"

func TestGenerateStableIDDistinguishesTransportSettings(t *testing.T) {
	base := &ProxyConfig{
		Protocol:  "vless",
		Server:    "example.com",
		Port:      443,
		UUID:      "00000000-0000-0000-0000-000000000000",
		Security:  "reality",
		PublicKey: "pub",
		Type:      "xhttp",
		Path:      "/a",
		Mode:      "stream-up",
	}

	other := *base
	other.Path = "/b"

	if base.GenerateStableID() == other.GenerateStableID() {
		t.Fatal("expected different stable IDs for different transport settings")
	}
}

func TestGenerateStableIDIgnoresRawOutboundContent(t *testing.T) {
	base := &ProxyConfig{
		Protocol:    "vless",
		Server:      "example.com",
		Port:        443,
		UUID:        "00000000-0000-0000-0000-000000000000",
		Security:    "reality",
		PublicKey:   "pub",
		Type:        "xhttp",
		Path:        "/a",
		Mode:        "stream-up",
		RawOutbound: `{"protocol":"vless","tag":"first","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"reality","xhttpSettings":{"path":"/a","mode":"stream-up"}}}`,
	}

	other := *base
	other.RawOutbound = `{"protocol":"vless","tag":"second","settings":{"vnext":[{"address":"other.example","port":8443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"reality","xhttpSettings":{"path":"/different","mode":"stream-up"}}}`

	if base.GenerateStableID() != other.GenerateStableID() {
		t.Fatal("expected raw outbound content to be ignored for stable ID")
	}
}

func TestGenerateStableIDUsesPositiveKCPMTU(t *testing.T) {
	base := &ProxyConfig{
		Protocol: "vless",
		Server:   "example.com",
		Port:     53,
		UUID:     "00000000-0000-0000-0000-000000000000",
		Type:     "kcp",
		KCPMTU:   130,
	}

	other := *base
	other.KCPMTU = 0

	if base.GenerateStableID() == other.GenerateStableID() {
		t.Fatal("expected positive KCP MTU to affect stable ID")
	}

	other.KCPMTU = 1300
	if base.GenerateStableID() == other.GenerateStableID() {
		t.Fatal("expected different positive KCP MTU to affect stable ID")
	}
}

func TestGenerateStableIDDistinguishesFinalMask(t *testing.T) {
	base := &ProxyConfig{
		Protocol:     "vless",
		Server:       "example.com",
		Port:         53,
		UUID:         "00000000-0000-0000-0000-000000000000",
		Type:         "kcp",
		KCPMTU:       130,
		RawFinalMask: `{"udp":[{"type":"xdns","settings":{"resolvers":["a+udp://1.1.1.1:53"]}}]}`,
	}

	other := *base
	other.RawFinalMask = `{"udp":[{"type":"xdns","settings":{"resolvers":["b+udp://8.8.8.8:53"]}}]}`

	if base.GenerateStableID() == other.GenerateStableID() {
		t.Fatal("expected different finalmask values to produce different stable IDs")
	}
}

func TestGenerateStableIDDistinguishesHysteriaSettings(t *testing.T) {
	base := &ProxyConfig{
		Protocol:             "hysteria",
		Server:               "example.com",
		Port:                 443,
		Type:                 "hysteria",
		Security:             "tls",
		HysteriaVersion:      2,
		HysteriaAuth:         "auth-a",
		PinnedPeerCertSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		VerifyPeerCertByName: "cdn.example.com",
		RawHysteriaSettings:  `{"version":2,"auth":"auth-a","udpIdleTimeout":60}`,
	}

	tests := []struct {
		name   string
		change func(*ProxyConfig)
	}{
		{name: "auth", change: func(config *ProxyConfig) { config.HysteriaAuth = "auth-b" }},
		{name: "pcs", change: func(config *ProxyConfig) {
			config.PinnedPeerCertSha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
		}},
		{name: "vcn", change: func(config *ProxyConfig) { config.VerifyPeerCertByName = "other.example.com" }},
		{name: "raw settings", change: func(config *ProxyConfig) {
			config.RawHysteriaSettings = `{"version":2,"auth":"auth-a","udpIdleTimeout":90}`
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			other := *base
			test.change(&other)
			if base.GenerateStableID() == other.GenerateStableID() {
				t.Fatalf("expected %s to affect Hysteria stable ID", test.name)
			}
		})
	}
}

func TestTLSPinsDoNotChangeExistingProtocolStableIDs(t *testing.T) {
	base := &ProxyConfig{
		Protocol: "vless",
		Server:   "example.com",
		Port:     443,
		UUID:     "00000000-0000-0000-0000-000000000000",
		Type:     "xhttp",
		Security: "tls",
	}
	other := *base
	other.PinnedPeerCertSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	other.VerifyPeerCertByName = "cdn.example.com"

	if base.GenerateStableID() != other.GenerateStableID() {
		t.Fatal("expected TLS pin fields to preserve existing non-Hysteria stable IDs")
	}
}

func TestValidateHysteriaVersion(t *testing.T) {
	config := &ProxyConfig{Protocol: "hysteria", Server: "example.com", Port: 443}
	if err := config.Validate(); err != nil {
		t.Fatalf("expected omitted Hysteria version to default to 2, got %v", err)
	}

	config.HysteriaVersion = 1
	if err := config.Validate(); err == nil {
		t.Fatal("expected Hysteria version 1 to be rejected")
	}
}
