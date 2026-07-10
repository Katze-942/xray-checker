package subscription

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"xray-checker/models"
	"xray-checker/xray"
)

const testPinnedPeerCertSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseMinimalHysteria2WithPCS(t *testing.T) {
	link := fmt.Sprintf("hysteria2://auth@example.com:443?sni=example.com&pcs=%s#minimal", testPinnedPeerCertSha256)
	result, err := NewParser().Parse(link)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(result.Configs) != 1 {
		t.Fatalf("expected one config, got %d", len(result.Configs))
	}

	config := result.Configs[0]
	if config.Protocol != "hysteria" || config.PinnedPeerCertSha256 != testPinnedPeerCertSha256 {
		t.Fatalf("unexpected minimal Hysteria config: protocol=%q pcs=%q", config.Protocol, config.PinnedPeerCertSha256)
	}
	generator := xray.NewConfigGenerator()
	configBytes, err := generator.GenerateConfig(result.Configs, 10000, "none")
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}
	if err := generator.ValidateConfig(configBytes); err != nil {
		t.Fatalf("expected minimal Hysteria config to build, got %v", err)
	}
}

func TestParseHysteria2ShareLinks(t *testing.T) {
	for _, scheme := range []string{"hysteria2", "hy2"} {
		t.Run(scheme, func(t *testing.T) {
			link := fmt.Sprintf("%s://auth-token@example.com:443?sni=cdn.example.com&pcs=%s&vcn=cdn.example.com&alpn=h3&fp=chrome&up=50%%20mbps&down=100%%20mbps&ports=20000-40000&hop-interval=30&obfs=salamander&obfs-password=secret#hy2", scheme, testPinnedPeerCertSha256)

			result, err := NewParser().Parse(link)
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}
			if len(result.Configs) != 1 {
				t.Fatalf("expected one config, got %d", len(result.Configs))
			}

			config := result.Configs[0]
			if config.Protocol != "hysteria" {
				t.Fatalf("expected hysteria protocol, got %q", config.Protocol)
			}
			if config.HysteriaVersion != 2 {
				t.Fatalf("expected Hysteria version 2, got %d", config.HysteriaVersion)
			}
			if config.HysteriaAuth != "auth-token" {
				t.Fatalf("expected Hysteria auth to be preserved, got %q", config.HysteriaAuth)
			}
			if config.Type != "hysteria" || config.Security != "tls" {
				t.Fatalf("expected hysteria over TLS, got network=%q security=%q", config.Type, config.Security)
			}
			if config.SNI != "cdn.example.com" {
				t.Fatalf("expected SNI cdn.example.com, got %q", config.SNI)
			}
			if config.PinnedPeerCertSha256 != testPinnedPeerCertSha256 {
				t.Fatalf("expected pcs to be preserved, got %q", config.PinnedPeerCertSha256)
			}
			if config.VerifyPeerCertByName != "cdn.example.com" {
				t.Fatalf("expected vcn to be preserved, got %q", config.VerifyPeerCertByName)
			}
			if !strings.Contains(config.RawHysteriaSettings, `"auth":"auth-token"`) {
				t.Fatalf("expected raw Hysteria settings to contain auth, got %s", config.RawHysteriaSettings)
			}
			if config.RawFinalMask == "" || config.RawFinalMask == "null" {
				t.Fatalf("expected Hysteria finalmask to be preserved, got %q", config.RawFinalMask)
			}
			if err := config.Validate(); err != nil {
				t.Fatalf("expected parsed Hysteria config to validate, got %v", err)
			}

			generator := xray.NewConfigGenerator()
			configBytes, err := generator.GenerateConfig([]*models.ProxyConfig{config}, 10000, "none")
			if err != nil {
				t.Fatalf("GenerateConfig returned error: %v", err)
			}
			if err := generator.ValidateConfig(configBytes); err != nil {
				t.Fatalf("expected parsed Hysteria config to build, got %v", err)
			}
		})
	}
}

func TestParseHysteriaJSONOutboundPreservesSettings(t *testing.T) {
	data := fmt.Sprintf(`{
		"outbounds":[{
			"protocol":"hysteria",
			"tag":"json-hy2",
			"settings":{"version":2,"address":"example.com","port":443},
			"streamSettings":{
				"network":"hysteria",
				"security":"tls",
				"tlsSettings":{"serverName":"cdn.example.com","pinnedPeerCertSha256":%q},
				"hysteriaSettings":{"version":2,"auth":"json-auth","udpIdleTimeout":90,"masquerade":{"type":"string","content":"ok","statusCode":200}}
			}
		}]
	}`, testPinnedPeerCertSha256)

	result, err := NewParser().Parse(data)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(result.Configs) != 1 {
		t.Fatalf("expected one config, got %d", len(result.Configs))
	}

	config := result.Configs[0]
	if config.Protocol != "hysteria" || config.HysteriaAuth != "json-auth" {
		t.Fatalf("unexpected parsed Hysteria config: protocol=%q auth=%q", config.Protocol, config.HysteriaAuth)
	}
	var rawSettings map[string]interface{}
	if err := json.Unmarshal([]byte(config.RawHysteriaSettings), &rawSettings); err != nil {
		t.Fatalf("failed to parse raw Hysteria settings: %v", err)
	}
	if rawSettings["udpIdleTimeout"] != float64(90) {
		t.Fatalf("expected udpIdleTimeout 90, got %v", rawSettings["udpIdleTimeout"])
	}
	masquerade, ok := rawSettings["masquerade"].(map[string]interface{})
	if !ok || masquerade["content"] != "ok" {
		t.Fatalf("expected masquerade settings to be preserved, got %v", rawSettings["masquerade"])
	}
}

func TestParseShareLinkReadsKCPMTU(t *testing.T) {
	link := `vless://00000000-0000-0000-0000-000000000000@example.com:53?type=kcp&mtu=130&security=none&fm=%7B%22udp%22%3A%5B%7B%22settings%22%3A%7B%22resolvers%22%3A%5B%22xdns%2Budp%3A%2F%2F1.1.1.1%3A53%22%5D%7D%2C%22type%22%3A%22xdns%22%7D%5D%7D#kcp`

	parsed := NewParser().parseShareLink(link)
	if parsed == nil {
		t.Fatal("expected link to parse")
	}

	if parsed.KCPMTU != 130 {
		t.Fatalf("expected KCP MTU 130, got %d", parsed.KCPMTU)
	}
	expectedFinalMask := `{"udp":[{"settings":{"resolvers":["xdns+udp://1.1.1.1:53"]},"type":"xdns"}]}`
	if parsed.RawFinalMask != expectedFinalMask {
		t.Fatalf("expected finalmask %s, got %s", expectedFinalMask, parsed.RawFinalMask)
	}
}

func TestOriginalLinkMatcherDistinguishesSameEndpointByPath(t *testing.T) {
	matcher := newOriginalLinkMatcher([]*originalLinkData{
		{
			Server:   "example.com",
			Port:     443,
			Type:     "xhttp",
			Path:     "/a",
			KCPMTU:   700,
			Security: "tls",
		},
		{
			Server:   "example.com",
			Port:     443,
			Type:     "xhttp",
			Path:     "/b",
			KCPMTU:   900,
			Security: "tls",
		},
	})

	first := matcher.match(&models.ProxyConfig{
		Server:   "example.com",
		Port:     443,
		Type:     "xhttp",
		Path:     "/b",
		Security: "tls",
	})
	if first == nil || first.KCPMTU != 900 {
		t.Fatalf("expected /b metadata, got %#v", first)
	}

	second := matcher.match(&models.ProxyConfig{
		Server:   "example.com",
		Port:     443,
		Type:     "xhttp",
		Path:     "/a",
		Security: "tls",
	})
	if second == nil || second.KCPMTU != 700 {
		t.Fatalf("expected /a metadata, got %#v", second)
	}
}

func TestOriginalLinkMatcherDistinguishesSameEndpointByFinalMask(t *testing.T) {
	firstFinalMask := `{"udp":[{"type":"xdns","settings":{"resolvers":["a+udp://1.1.1.1:53"]}}]}`
	secondFinalMask := `{"udp":[{"type":"xdns","settings":{"resolvers":["b+udp://8.8.8.8:53"]}}]}`
	matcher := newOriginalLinkMatcher([]*originalLinkData{
		{
			Server:       "example.com",
			Port:         53,
			UUID:         "00000000-0000-0000-0000-000000000000",
			Type:         "kcp",
			KCPMTU:       130,
			RawFinalMask: firstFinalMask,
		},
		{
			Server:       "example.com",
			Port:         53,
			UUID:         "00000000-0000-0000-0000-000000000000",
			Type:         "kcp",
			KCPMTU:       130,
			RawFinalMask: secondFinalMask,
		},
	})

	first := matcher.match(&models.ProxyConfig{
		Server:       "example.com",
		Port:         53,
		UUID:         "00000000-0000-0000-0000-000000000000",
		Type:         "kcp",
		RawFinalMask: secondFinalMask,
	})
	if first == nil || first.RawFinalMask != secondFinalMask {
		t.Fatalf("expected second finalmask metadata, got %#v", first)
	}

	second := matcher.match(&models.ProxyConfig{
		Server:       "example.com",
		Port:         53,
		UUID:         "00000000-0000-0000-0000-000000000000",
		Type:         "kcp",
		RawFinalMask: firstFinalMask,
	})
	if second == nil || second.RawFinalMask != firstFinalMask {
		t.Fatalf("expected first finalmask metadata, got %#v", second)
	}
}

func TestOriginalLinkMatcherUsesNameWhenFinalMaskFormattingDiffers(t *testing.T) {
	linkFinalMask := `{"udp":[{"type":"xdns","settings":{"resolvers":["a+udp://1.1.1.1:53"]}}]}`
	rawFinalMask := `{"tcp":[],"udp":[{"settings":{"resolvers":["a+udp://1.1.1.1:53"]},"type":"xdns"}]}`
	matcher := newOriginalLinkMatcher([]*originalLinkData{
		{
			Server:       "example.com",
			Port:         53,
			Name:         "xdns",
			UUID:         "00000000-0000-0000-0000-000000000000",
			Type:         "kcp",
			KCPMTU:       130,
			RawFinalMask: linkFinalMask,
		},
	})

	match := matcher.match(&models.ProxyConfig{
		Server:       "example.com",
		Port:         53,
		Name:         "xdns",
		UUID:         "00000000-0000-0000-0000-000000000000",
		Type:         "kcp",
		RawFinalMask: rawFinalMask,
	})
	if match == nil || match.KCPMTU != 130 {
		t.Fatalf("expected same-name finalmask metadata, got %#v", match)
	}
}
