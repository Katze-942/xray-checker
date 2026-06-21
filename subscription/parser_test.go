package subscription

import (
	"testing"

	"xray-checker/models"
)

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
