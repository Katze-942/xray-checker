package xray

import (
	"encoding/json"
	"testing"

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
		Server:   "example.com",
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
		Server:       "example.com",
		Port:         53,
		UUID:         "00000000-0000-0000-0000-000000000000",
		KCPMTU:       130,
		Type:         "kcp",
		RawFinalMask: `{"udp":[{"type":"xdns","settings":{"resolvers":["example+udp://1.1.1.1:53"]}}]}`,
		RawOutbound: `{
			"protocol":"vless",
			"settings":{
				"vnext":[{
					"address":"example.com",
					"port":53,
					"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]
				}]
			},
			"streamSettings":{
				"network":"kcp",
				"security":"none",
				"kcpSettings":{"header":{"type":"none"},"seed":""},
				"finalmask":{"udp":[{"type":"xdns","settings":{"resolvers":["example+udp://8.8.8.8:53"]}}]}
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
