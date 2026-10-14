package xray

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"xray-checker/models"
)

func TestGenerateConfigMergesRawStreamWithCanonicalSettings(t *testing.T) {
	proxy := &models.ProxyConfig{
		Index:         0,
		Name:          "raw",
		Protocol:      "vless",
		Server:        "resolved.example",
		Port:          8443,
		UUID:          "00000000-0000-0000-0000-000000000000",
		Encryption:    "mlkem",
		Type:          "xhttp",
		Security:      "tls",
		SNI:           "resolved.example",
		AllowInsecure: true,
		Path:          "/canonical",
		Mode:          "stream-up",
		RawOutbound: `{
			"mux":null,
			"protocol":"vless",
			"tag":"provider-tag",
			"sendThrough":"display name from libXray",
			"settings":{
				"vnext":[{
					"address":"original.example",
					"port":443,
					"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]
				},{
					"address":"secondary.example",
					"port":443,
					"users":[{"id":"22222222-2222-2222-2222-222222222222","encryption":"none"}]
				}]
			},
			"streamSettings":{
				"network":"xhttp",
				"security":"tls",
				"tlsSettings":{"serverName":"raw.example","allowInsecure":false,"fingerprint":"chrome"},
				"xhttpSettings":{"path":"/raw","mode":"packet-up","extra":{"noSSEHeader":true,"downloadSettings":null}}
			}
		}`,
	}

	configBytes, err := NewConfigGenerator().GenerateConfig([]*models.ProxyConfig{proxy}, 10000, "none")
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}

	var config struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatalf("failed to unmarshal generated config: %v", err)
	}

	var outbound map[string]interface{}
	for _, candidate := range config.Outbounds {
		if candidate["tag"] == "raw_0" {
			outbound = candidate
			break
		}
	}
	if outbound == nil {
		t.Fatal("raw outbound not found in generated config")
	}
	if _, ok := outbound["sendThrough"]; ok {
		t.Fatal("expected raw outbound top-level sendThrough to be ignored")
	}
	if _, ok := outbound["mux"]; ok {
		t.Fatal("expected raw outbound top-level mux to be ignored")
	}

	settings := outbound["settings"].(map[string]interface{})
	vnext := settings["vnext"].([]interface{})[0].(map[string]interface{})
	if len(settings["vnext"].([]interface{})) != 1 {
		t.Fatal("expected canonical settings to contain one vnext endpoint")
	}
	if vnext["address"] != "resolved.example" {
		t.Fatalf("expected canonical endpoint address, got %v", vnext["address"])
	}
	if int(vnext["port"].(float64)) != 8443 {
		t.Fatalf("expected canonical endpoint port, got %v", vnext["port"])
	}
	user := vnext["users"].([]interface{})[0].(map[string]interface{})
	if user["id"] != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("expected canonical user ID, got %v", user["id"])
	}
	if user["encryption"] != "mlkem" {
		t.Fatalf("expected canonical encryption, got %v", user["encryption"])
	}

	streamSettings := outbound["streamSettings"].(map[string]interface{})
	if streamSettings["network"] != "xhttp" {
		t.Fatalf("expected canonical network, got %v", streamSettings["network"])
	}
	tlsSettings := streamSettings["tlsSettings"].(map[string]interface{})
	if tlsSettings["serverName"] != "resolved.example" {
		t.Fatalf("expected canonical TLS serverName, got %v", tlsSettings["serverName"])
	}
	if tlsSettings["allowInsecure"] != true {
		t.Fatalf("expected canonical allowInsecure, got %v", tlsSettings["allowInsecure"])
	}
	xhttpSettings, ok := streamSettings["xhttpSettings"].(map[string]interface{})
	if !ok {
		t.Fatal("expected raw xhttpSettings to be preserved")
	}
	if xhttpSettings["path"] != "/canonical" {
		t.Fatalf("expected canonical xhttp path, got %v", xhttpSettings["path"])
	}
	if xhttpSettings["mode"] != "stream-up" {
		t.Fatalf("expected canonical xhttp mode, got %v", xhttpSettings["mode"])
	}
	extra := xhttpSettings["extra"].(map[string]interface{})
	if extra["noSSEHeader"] != true {
		t.Fatalf("expected raw xhttp extra to be preserved, got %v", extra)
	}
	if _, ok := extra["downloadSettings"]; ok {
		t.Fatal("expected null xhttp extra fields to be stripped")
	}
}

func TestGenerateConfigPreservesPositiveKCPMTU(t *testing.T) {
	proxy := &models.ProxyConfig{
		Index:    0,
		Name:     "raw",
		Protocol: "vless",
		Server:   "127.0.0.1",
		Port:     53,
		UUID:     "00000000-0000-0000-0000-000000000000",
		KCPMTU:   130,
		Type:     "kcp",
	}

	configBytes, err := NewConfigGenerator().GenerateConfig([]*models.ProxyConfig{proxy}, 10000, "none")
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}

	var config struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatalf("failed to unmarshal generated config: %v", err)
	}

	var outbound map[string]interface{}
	for _, candidate := range config.Outbounds {
		if candidate["tag"] == "raw_0" {
			outbound = candidate
			break
		}
	}
	if outbound == nil {
		t.Fatal("generated outbound not found")
	}

	streamSettings := outbound["streamSettings"].(map[string]interface{})
	kcpSettings := streamSettings["kcpSettings"].(map[string]interface{})
	if int(kcpSettings["mtu"].(float64)) != 130 {
		t.Fatalf("expected KCP MTU 130, got %v", kcpSettings["mtu"])
	}
	if _, ok := kcpSettings["header"]; ok {
		t.Fatal("expected KCP header to be omitted")
	}
	if _, ok := kcpSettings["seed"]; ok {
		t.Fatal("expected KCP seed to be omitted")
	}
	if err := NewConfigGenerator().ValidateConfig(configBytes); err != nil {
		t.Fatalf("expected generated KCP config to build, got %v", err)
	}
}

func TestGenerateConfigPreservesFinalMaskAndStripsRemovedKCPFields(t *testing.T) {
	proxy := &models.ProxyConfig{
		Index:        0,
		Name:         "xdns",
		Protocol:     "vless",
		Server:       "127.0.0.1",
		Port:         53,
		UUID:         "00000000-0000-0000-0000-000000000000",
		KCPMTU:       130,
		Type:         "kcp",
		RawFinalMask: `{"udp":[{"type":"xdns","settings":{"resolvers":["example+udp://1.1.1.1:53"]}}]}`,
		RawOutbound: `{
			"protocol":"vless",
			"settings":{
				"vnext":[{
					"address":"127.0.0.1",
					"port":53,
					"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]
				}]
			},
			"streamSettings":{
				"network":"kcp",
				"security":"none",
				"kcpSettings":{"header":{"type":"none"},"seed":""},
			"finalmask":{"udp":[{"type":"xdns","settings":{"domains":[{"name":"raw.example","types":[16],"edns0":4096}],"resolvers":[{"type":"udp","settings":{"addr":"8.8.8.8:53"}}]}}]}
			}
		}`,
	}

	generator := NewConfigGenerator()
	configBytes, err := generator.GenerateConfig([]*models.ProxyConfig{proxy}, 10000, "none")
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}

	var config struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatalf("failed to unmarshal generated config: %v", err)
	}

	var outbound map[string]interface{}
	for _, candidate := range config.Outbounds {
		if candidate["tag"] == "xdns_0" {
			outbound = candidate
			break
		}
	}
	if outbound == nil {
		t.Fatal("generated outbound not found")
	}

	streamSettings := outbound["streamSettings"].(map[string]interface{})
	finalMask := streamSettings["finalmask"].(map[string]interface{})
	udp := finalMask["udp"].([]interface{})
	udpMask := udp[0].(map[string]interface{})
	if udpMask["type"] != "xdns" {
		t.Fatalf("expected XDNS finalmask, got %v", udpMask["type"])
	}
	assertNormalizedXDNSSettings(t, udpMask["settings"].(map[string]interface{}), "example", "udp://1.1.1.1:53", []int{16})
	kcpSettings := streamSettings["kcpSettings"].(map[string]interface{})
	if int(kcpSettings["mtu"].(float64)) != 130 {
		t.Fatalf("expected KCP MTU 130, got %v", kcpSettings["mtu"])
	}
	if _, ok := kcpSettings["header"]; ok {
		t.Fatal("expected removed KCP header field to be stripped")
	}
	if _, ok := kcpSettings["seed"]; ok {
		t.Fatal("expected removed KCP seed field to be stripped")
	}
	if err := generator.ValidateConfig(configBytes); err != nil {
		t.Fatalf("expected generated XDNS config to build, got %v", err)
	}
}

func TestGenerateConfigNormalizesVersion26930XDNSFinalMask(t *testing.T) {
	proxy := &models.ProxyConfig{
		Index:    0,
		Name:     "xdns",
		Protocol: "vless",
		Server:   "127.0.0.1",
		Port:     53,
		UUID:     "00000000-0000-0000-0000-000000000000",
		Type:     "kcp",
		RawOutbound: `{
			"protocol":"vless",
			"streamSettings":{
				"network":"kcp",
				"security":"none",
				"finalmask":{"udp":[{"type":"xdns","settings":{
					"domains":[{"name":"x99.example","types":[1,16,28],"edns0":4096}],
					"resolvers":[{"type":"udp","settings":{"addr":"127.0.0.1:53"}}]
				}}]}
			}
		}`,
	}

	generator := NewConfigGenerator()
	configBytes, err := generator.GenerateConfig([]*models.ProxyConfig{proxy}, 10000, "none")
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}
	if err := generator.ValidateConfig(configBytes); err != nil {
		t.Fatalf("expected v26.9.30 XDNS config to build after normalization, got %v", err)
	}

	settings := generatedXDNSSettings(t, configBytes)
	assertNormalizedXDNSSettings(t, settings, "x99.example", "udp://127.0.0.1:53", []int{1, 16, 28})
}

func TestGenerateConfigPreservesLegacyXDNSRecordType(t *testing.T) {
	proxy := &models.ProxyConfig{
		Index:        0,
		Name:         "xdns",
		Protocol:     "vless",
		Server:       "127.0.0.1",
		Port:         53,
		UUID:         "00000000-0000-0000-0000-000000000000",
		Type:         "kcp",
		RawFinalMask: `{"udp":[{"type":"xdns","settings":{"resolvers":["x99.example:aaaa+udp://127.0.0.1:53"]}}]}`,
	}

	generator := NewConfigGenerator()
	configBytes, err := generator.GenerateConfig([]*models.ProxyConfig{proxy}, 10000, "none")
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}
	if err := generator.ValidateConfig(configBytes); err != nil {
		t.Fatalf("expected legacy XDNS record type to build after normalization, got %v", err)
	}

	settings := generatedXDNSSettings(t, configBytes)
	assertNormalizedXDNSSettings(t, settings, "x99.example", "udp://127.0.0.1:53", []int{28})
}

func TestRunnerProcessesXDNSAndStopsCleanly(t *testing.T) {
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start local DNS sink: %v", err)
	}
	defer dnsConn.Close()

	dnsRequest := make(chan struct{}, 1)
	go func() {
		buffer := make([]byte, 4096)
		for {
			if _, _, err := dnsConn.ReadFrom(buffer); err != nil {
				return
			}
			select {
			case dnsRequest <- struct{}{}:
			default:
			}
		}
	}()

	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve local SOCKS port: %v", err)
	}
	inboundPort := portListener.Addr().(*net.TCPAddr).Port
	if err := portListener.Close(); err != nil {
		t.Fatalf("failed to release local SOCKS port: %v", err)
	}

	proxy := &models.ProxyConfig{
		Index:        0,
		Name:         "xdns-smoke",
		Protocol:     "vless",
		Server:       "127.0.0.1",
		Port:         9,
		UUID:         "00000000-0000-0000-0000-000000000000",
		KCPMTU:       130,
		Type:         "kcp",
		RawFinalMask: `{"udp":[{"type":"xdns","settings":{"domains":[{"names":["example.test"],"types":[16],"edns0":4096}],"resolvers":[{"addrs":["udp://` + dnsConn.LocalAddr().String() + `"]}]}}]}`,
	}
	configBytes, err := NewConfigGenerator().GenerateConfig([]*models.ProxyConfig{proxy}, inboundPort, "none")
	if err != nil {
		t.Fatalf("failed to generate XDNS config: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatalf("failed to write XDNS config: %v", err)
	}

	runner := NewRunner(configPath)
	if err := runner.Start(); err != nil {
		t.Fatalf("failed to start Xray with XDNS config: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			stopResult := make(chan struct{}, 1)
			go func() {
				_ = runner.Stop()
				stopResult <- struct{}{}
			}()
			select {
			case <-stopResult:
			case <-time.After(5 * time.Second):
			}
		}
	}()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(inboundPort)), time.Second)
	if err != nil {
		t.Fatalf("failed to connect to local SOCKS inbound: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("failed to write SOCKS greeting: %v", err)
	}
	var greetingReply [2]byte
	if _, err := io.ReadFull(conn, greetingReply[:]); err != nil {
		t.Fatalf("failed to read SOCKS greeting reply: %v", err)
	}
	if greetingReply != [2]byte{5, 0} {
		t.Fatalf("unexpected SOCKS greeting reply: %v", greetingReply)
	}
	if _, err := conn.Write([]byte{5, 1, 0, 1, 1, 1, 1, 1, 0, 80}); err != nil {
		t.Fatalf("failed to request a proxied connection: %v", err)
	}

	select {
	case <-dnsRequest:
	case <-time.After(3 * time.Second):
		_ = conn.Close()
		t.Fatal("Xray did not send an XDNS request to the configured resolver")
	}
	_ = conn.Close()

	stopResult := make(chan error, 1)
	go func() { stopResult <- runner.Stop() }()
	select {
	case err := <-stopResult:
		if err != nil {
			t.Fatalf("failed to stop Xray with XDNS active: %v", err)
		}
		stopped = true
	case <-time.After(5 * time.Second):
		stopped = true
		t.Fatal("Xray did not stop promptly after XDNS activity")
	}
}

func generatedXDNSSettings(t *testing.T, configBytes []byte) map[string]interface{} {
	t.Helper()
	var config struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatalf("failed to unmarshal generated config: %v", err)
	}
	for _, outbound := range config.Outbounds {
		if outbound["tag"] != "xdns_0" {
			continue
		}
		streamSettings, ok := outbound["streamSettings"].(map[string]interface{})
		if !ok {
			t.Fatal("generated XDNS stream settings not found")
		}
		finalMask, ok := streamSettings["finalmask"].(map[string]interface{})
		if !ok {
			t.Fatal("generated XDNS finalmask not found")
		}
		udp, ok := finalMask["udp"].([]interface{})
		if !ok || len(udp) != 1 {
			t.Fatalf("expected one UDP finalmask, got %v", finalMask["udp"])
		}
		mask, ok := udp[0].(map[string]interface{})
		if !ok || mask["type"] != "xdns" {
			t.Fatalf("expected XDNS finalmask, got %v", udp[0])
		}
		settings, ok := mask["settings"].(map[string]interface{})
		if !ok {
			t.Fatal("generated XDNS settings not found")
		}
		return settings
	}
	t.Fatal("generated XDNS outbound not found")
	return nil
}

func assertNormalizedXDNSSettings(t *testing.T, settings map[string]interface{}, wantDomain, wantResolver string, wantTypes []int) {
	t.Helper()
	domains, ok := settings["domains"].([]interface{})
	if !ok || len(domains) != 1 {
		t.Fatalf("expected one normalized XDNS domain, got %v", settings["domains"])
	}
	domain, ok := domains[0].(map[string]interface{})
	if !ok {
		t.Fatalf("invalid normalized XDNS domain: %v", domains[0])
	}
	names, ok := domain["names"].([]interface{})
	if !ok || len(names) != 1 || names[0] != wantDomain {
		t.Fatalf("expected normalized domain name %q, got %v", wantDomain, domain["names"])
	}
	if _, hasOldName := domain["name"]; hasOldName {
		t.Fatalf("legacy domain field was not removed: %v", domain)
	}
	types, ok := domain["types"].([]interface{})
	if !ok || len(types) != len(wantTypes) {
		t.Fatalf("expected XDNS query types %v, got %v", wantTypes, domain["types"])
	}
	for i, want := range wantTypes {
		if types[i] != float64(want) {
			t.Fatalf("expected XDNS query types %v, got %v", wantTypes, domain["types"])
		}
	}
	resolvers, ok := settings["resolvers"].([]interface{})
	if !ok || len(resolvers) != 1 {
		t.Fatalf("expected one normalized XDNS resolver, got %v", settings["resolvers"])
	}
	resolver, ok := resolvers[0].(map[string]interface{})
	if !ok {
		t.Fatalf("invalid normalized XDNS resolver: %v", resolvers[0])
	}
	addrs, ok := resolver["addrs"].([]interface{})
	if !ok || len(addrs) != 1 || addrs[0] != wantResolver {
		t.Fatalf("expected normalized XDNS resolver %q, got %v", wantResolver, resolver["addrs"])
	}
	if _, hasOldType := resolver["type"]; hasOldType {
		t.Fatalf("legacy resolver fields were not removed: %v", resolver)
	}
	if _, hasOldSettings := resolver["settings"]; hasOldSettings {
		t.Fatalf("legacy resolver fields were not removed: %v", resolver)
	}
}

func TestGenerateHysteria2ConfigPreservesTLSAndTransportSettings(t *testing.T) {
	const pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	proxy := &models.ProxyConfig{
		Index:                0,
		Name:                 "hy2",
		Protocol:             "hysteria",
		Server:               "resolved.example",
		Port:                 8443,
		Type:                 "hysteria",
		Security:             "tls",
		SNI:                  "cdn.example.com",
		Fingerprint:          "chrome",
		ALPN:                 []string{"h3"},
		HysteriaVersion:      2,
		HysteriaAuth:         "canonical-auth",
		PinnedPeerCertSha256: pin,
		VerifyPeerCertByName: "cdn.example.com",
		RawHysteriaSettings:  `{"version":2,"auth":"raw-auth","udpIdleTimeout":90,"masquerade":{"type":"string","content":"ok","statusCode":200}}`,
		RawFinalMask:         `{"udp":[{"type":"salamander","settings":{"password":"secret"}}]}`,
		RawOutbound: `{
			"protocol":"hysteria",
			"settings":{"version":2,"address":"original.example","port":443},
			"streamSettings":{
				"network":"hysteria",
				"security":"tls",
				"tlsSettings":{"serverName":"raw.example","pinnedPeerCertSha256":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
				"hysteriaSettings":{"version":2,"auth":"raw-auth","udpIdleTimeout":90,"masquerade":{"type":"string","content":"ok","statusCode":200}}
			}
		}`,
	}

	generator := NewConfigGenerator()
	configBytes, err := generator.GenerateConfig([]*models.ProxyConfig{proxy}, 10000, "none")
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}

	var config struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatalf("failed to unmarshal generated config: %v", err)
	}

	var outbound map[string]interface{}
	for _, candidate := range config.Outbounds {
		if candidate["tag"] == "hy2_0" {
			outbound = candidate
			break
		}
	}
	if outbound == nil {
		t.Fatal("generated Hysteria outbound not found")
	}

	settings := outbound["settings"].(map[string]interface{})
	if settings["address"] != "resolved.example" || int(settings["port"].(float64)) != 8443 {
		t.Fatalf("expected canonical Hysteria endpoint, got %v", settings)
	}
	if int(settings["version"].(float64)) != 2 {
		t.Fatalf("expected Hysteria version 2, got %v", settings["version"])
	}

	streamSettings := outbound["streamSettings"].(map[string]interface{})
	if streamSettings["network"] != "hysteria" || streamSettings["security"] != "tls" {
		t.Fatalf("expected hysteria over TLS, got %v", streamSettings)
	}
	hysteriaSettings := streamSettings["hysteriaSettings"].(map[string]interface{})
	if hysteriaSettings["auth"] != "canonical-auth" {
		t.Fatalf("expected canonical Hysteria auth, got %v", hysteriaSettings["auth"])
	}
	if int(hysteriaSettings["udpIdleTimeout"].(float64)) != 90 {
		t.Fatalf("expected raw udpIdleTimeout to be preserved, got %v", hysteriaSettings["udpIdleTimeout"])
	}

	tlsSettings := streamSettings["tlsSettings"].(map[string]interface{})
	if tlsSettings["serverName"] != "cdn.example.com" {
		t.Fatalf("expected canonical TLS serverName, got %v", tlsSettings["serverName"])
	}
	if tlsSettings["pinnedPeerCertSha256"] != pin {
		t.Fatalf("expected canonical pcs, got %v", tlsSettings["pinnedPeerCertSha256"])
	}
	if tlsSettings["verifyPeerCertByName"] != "cdn.example.com" {
		t.Fatalf("expected vcn to be preserved, got %v", tlsSettings["verifyPeerCertByName"])
	}
	if _, ok := streamSettings["finalmask"].(map[string]interface{}); !ok {
		t.Fatalf("expected Hysteria finalmask to be preserved, got %v", streamSettings["finalmask"])
	}

	if err := generator.ValidateConfig(configBytes); err != nil {
		t.Fatalf("expected generated Hysteria config to build, got %v", err)
	}
}

func TestValidateHysteria2ConfigRejectsInvalidPCS(t *testing.T) {
	proxy := &models.ProxyConfig{
		Name:                 "hy2",
		Protocol:             "hysteria",
		Server:               "example.com",
		Port:                 443,
		Type:                 "hysteria",
		Security:             "tls",
		SNI:                  "example.com",
		HysteriaVersion:      2,
		HysteriaAuth:         "auth",
		PinnedPeerCertSha256: "invalid",
	}

	generator := NewConfigGenerator()
	configBytes, err := generator.GenerateConfig([]*models.ProxyConfig{proxy}, 10000, "none")
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}
	if err := generator.ValidateConfig(configBytes); err == nil {
		t.Fatal("expected invalid pcs to be rejected by Xray config validation")
	}
}
