package xray

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"xray-checker/logger"
	"xray-checker/models"

	"github.com/xtls/xray-core/infra/conf/serial"
)

type ConfigGenerator struct{}

func NewConfigGenerator() *ConfigGenerator {
	return &ConfigGenerator{}
}

func (g *ConfigGenerator) GenerateConfig(proxies []*models.ProxyConfig, startPort int, xrayLogLevel string) ([]byte, error) {
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": xrayLogLevel,
		},
		"inbounds":  g.generateInbounds(proxies, startPort),
		"outbounds": g.generateOutbounds(proxies),
		"routing":   g.generateRouting(proxies),
	}

	return json.MarshalIndent(config, "", "  ")
}

func (g *ConfigGenerator) GenerateAndSaveConfig(proxies []*models.ProxyConfig, startPort int, filename string, xrayLogLevel string) error {
	configBytes, err := g.GenerateConfig(proxies, startPort, xrayLogLevel)
	if err != nil {
		return fmt.Errorf("error generating config: %v", err)
	}

	if err := g.ValidateConfig(configBytes); err != nil {
		logger.Warn("Config validation failed: %v", err)
	}

	if err := os.WriteFile(filename, configBytes, 0644); err != nil {
		return fmt.Errorf("error saving config: %v", err)
	}

	return nil
}

func (g *ConfigGenerator) ValidateConfig(configBytes []byte) error {
	var config map[string]interface{}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	required := []string{"inbounds", "outbounds", "routing"}
	for _, field := range required {
		if _, ok := config[field]; !ok {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	xrayConfig, err := serial.DecodeJSONConfig(bytes.NewReader(configBytes))
	if err != nil {
		return fmt.Errorf("error decoding config: %v", err)
	}
	if _, err := xrayConfig.Build(); err != nil {
		return fmt.Errorf("error building config: %v", err)
	}

	return nil
}

func (g *ConfigGenerator) generateInbounds(proxies []*models.ProxyConfig, startPort int) []map[string]interface{} {
	var inbounds []map[string]interface{}

	for _, proxy := range proxies {
		inbound := map[string]interface{}{
			"listen":   "127.0.0.1",
			"port":     startPort + proxy.Index,
			"protocol": "socks",
			"tag":      fmt.Sprintf("%s_%s_%d_Inbound", proxy.Name, proxy.Protocol, proxy.Index),
			"sniffing": map[string]interface{}{
				"enabled":      true,
				"destOverride": []string{"http", "tls", "quic"},
				"routeOnly":    true,
			},
			"settings": map[string]interface{}{
				"auth":      "noauth",
				"udp":       true,
				"userLevel": 0,
			},
		}
		inbounds = append(inbounds, inbound)
	}

	return inbounds
}

func (g *ConfigGenerator) generateOutbounds(proxies []*models.ProxyConfig) []map[string]interface{} {
	var outbounds []map[string]interface{}

	outbounds = append(outbounds, map[string]interface{}{
		"tag":      "direct",
		"protocol": "freedom",
		"settings": map[string]interface{}{"domainStrategy": "UseIP"},
	})

	outbounds = append(outbounds, map[string]interface{}{
		"tag":      "block",
		"protocol": "blackhole",
		"settings": map[string]interface{}{},
	})

	for _, proxy := range proxies {
		outbound := g.generateProxyOutbound(proxy)
		outbounds = append(outbounds, outbound)
	}

	return outbounds
}

func (g *ConfigGenerator) generateProxyOutbound(proxy *models.ProxyConfig) map[string]interface{} {
	outbound := map[string]interface{}{
		"tag":      fmt.Sprintf("%s_%d", proxy.Name, proxy.Index),
		"protocol": proxy.Protocol,
	}

	switch proxy.Protocol {
	case "vless":
		user := map[string]interface{}{
			"id":    proxy.UUID,
			"level": proxy.GetUserLevel(),
		}
		if proxy.Encryption != "" {
			user["encryption"] = proxy.Encryption
		} else {
			user["encryption"] = "none"
		}
		if proxy.Flow != "" {
			user["flow"] = proxy.Flow
		}
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{"address": proxy.Server, "port": proxy.Port, "users": []map[string]interface{}{user}},
			},
		}

	case "vmess":
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": proxy.Server,
					"port":    proxy.Port,
					"users": []map[string]interface{}{
						{
							"id":       proxy.UUID,
							"alterId":  proxy.GetAlterId(),
							"security": proxy.GetVMessSecurity(),
							"level":    proxy.GetUserLevel(),
						},
					},
				},
			},
		}

	case "trojan":
		server := map[string]interface{}{
			"address":  proxy.Server,
			"port":     proxy.Port,
			"password": proxy.Password,
		}
		if proxy.Flow != "" {
			server["flow"] = proxy.Flow
		}
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{server},
		}

	case "shadowsocks":
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  proxy.Server,
					"port":     proxy.Port,
					"method":   proxy.Method,
					"password": proxy.Password,
				},
			},
		}
	}

	outbound["streamSettings"] = g.generateRuntimeStreamSettings(proxy)

	return outbound
}

func (g *ConfigGenerator) generateRuntimeStreamSettings(proxy *models.ProxyConfig) map[string]interface{} {
	streamSettings := g.generateStreamSettings(proxy)
	rawStreamSettings, ok := g.rawStreamSettings(proxy)
	if ok {
		g.mergeMaps(streamSettings, rawStreamSettings)
		g.enforceStreamSettingsFromProxy(streamSettings, proxy)
	}
	g.applyFinalMask(streamSettings, proxy)

	g.pruneNilValues(streamSettings)
	return streamSettings
}

func (g *ConfigGenerator) rawStreamSettings(proxy *models.ProxyConfig) (map[string]interface{}, bool) {
	if proxy.RawOutbound == "" {
		return nil, false
	}

	var outbound struct {
		StreamSettings map[string]interface{} `json:"streamSettings"`
	}
	if err := json.Unmarshal([]byte(proxy.RawOutbound), &outbound); err != nil {
		logger.Warn("Failed to parse raw outbound for %s: %v", proxy.Name, err)
		return nil, false
	}
	if len(outbound.StreamSettings) == 0 {
		return nil, false
	}

	g.pruneNilValues(outbound.StreamSettings)
	g.normalizeKCPSettings(outbound.StreamSettings, proxy)
	return outbound.StreamSettings, true
}

func (g *ConfigGenerator) pruneNilValues(value interface{}) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			if child == nil {
				delete(typed, key)
				continue
			}
			g.pruneNilValues(child)
		}
	case []interface{}:
		for _, child := range typed {
			g.pruneNilValues(child)
		}
	}
}

func (g *ConfigGenerator) mergeMaps(dst, src map[string]interface{}) {
	for key, srcValue := range src {
		srcMap, srcIsMap := srcValue.(map[string]interface{})
		dstMap, dstIsMap := dst[key].(map[string]interface{})
		if srcIsMap && dstIsMap {
			g.mergeMaps(dstMap, srcMap)
			continue
		}
		dst[key] = srcValue
	}
}

func (g *ConfigGenerator) enforceStreamSettingsFromProxy(streamSettings map[string]interface{}, proxy *models.ProxyConfig) {
	network := proxy.Type
	if network == "" {
		network = "tcp"
	}
	security := proxy.Security
	if security == "" {
		security = "none"
	}

	streamSettings["network"] = network
	streamSettings["security"] = security

	switch security {
	case "tls":
		tlsSettings := ensureMap(streamSettings, "tlsSettings")
		tlsSettings["serverName"] = proxy.SNI
		tlsSettings["allowInsecure"] = proxy.AllowInsecure
		if proxy.Fingerprint != "" {
			tlsSettings["fingerprint"] = proxy.Fingerprint
		}
		if len(proxy.ALPN) > 0 {
			tlsSettings["alpn"] = proxy.ALPN
		}
	case "reality":
		realitySettings := ensureMap(streamSettings, "realitySettings")
		realitySettings["serverName"] = proxy.SNI
		realitySettings["fingerprint"] = proxy.Fingerprint
		realitySettings["publicKey"] = proxy.PublicKey
		if proxy.ShortID != "" {
			realitySettings["shortId"] = proxy.ShortID
		}
	}

	switch network {
	case "xhttp":
		g.enforceHTTPStyleSettings(ensureMap(streamSettings, "xhttpSettings"), proxy)
	case "splithttp":
		g.enforceHTTPStyleSettings(ensureMap(streamSettings, "splithttpSettings"), proxy)
	case "kcp":
		g.normalizeKCPSettings(streamSettings, proxy)
	case "mkcp":
		g.normalizeKCPSettings(streamSettings, proxy)
	}
}

func (g *ConfigGenerator) enforceHTTPStyleSettings(settings map[string]interface{}, proxy *models.ProxyConfig) {
	if proxy.Path != "" {
		settings["path"] = proxy.Path
	}
	if proxy.Host != "" {
		settings["host"] = proxy.Host
	}
	if proxy.Mode != "" {
		settings["mode"] = proxy.Mode
	}
}

func ensureMap(parent map[string]interface{}, key string) map[string]interface{} {
	if value, ok := parent[key].(map[string]interface{}); ok {
		return value
	}
	value := map[string]interface{}{}
	parent[key] = value
	return value
}

func (g *ConfigGenerator) normalizeKCPSettings(streamSettings map[string]interface{}, proxy *models.ProxyConfig) {
	network, _ := streamSettings["network"].(string)
	if network != "kcp" && network != "mkcp" {
		return
	}

	kcpSettings := ensureMap(streamSettings, "kcpSettings")
	delete(kcpSettings, "header")
	delete(kcpSettings, "seed")

	if isValidKCPMTU(proxy.KCPMTU) {
		kcpSettings["mtu"] = proxy.KCPMTU
	} else {
		delete(kcpSettings, "mtu")
	}
}

func isValidKCPMTU(mtu int) bool {
	return mtu > 0
}

func (g *ConfigGenerator) applyFinalMask(streamSettings map[string]interface{}, proxy *models.ProxyConfig) {
	if proxy.RawFinalMask == "" {
		return
	}
	var finalMask interface{}
	if err := json.Unmarshal([]byte(proxy.RawFinalMask), &finalMask); err != nil {
		logger.Warn("Failed to parse finalmask for %s: %v", proxy.Name, err)
		return
	}
	streamSettings["finalmask"] = finalMask
}

func (g *ConfigGenerator) generateStreamSettings(proxy *models.ProxyConfig) map[string]interface{} {
	network := proxy.Type
	if network == "" {
		network = "tcp"
	}

	security := proxy.Security
	if security == "" {
		security = "none"
	}

	ss := map[string]interface{}{
		"network":  network,
		"security": security,
		"sockopt":  map[string]interface{}{},
	}

	if security == "tls" {
		tlsSettings := map[string]interface{}{
			"serverName":    proxy.SNI,
			"allowInsecure": proxy.AllowInsecure,
		}
		if proxy.Fingerprint != "" {
			tlsSettings["fingerprint"] = proxy.Fingerprint
		}
		if len(proxy.ALPN) > 0 {
			tlsSettings["alpn"] = proxy.ALPN
		}
		ss["tlsSettings"] = tlsSettings
	}

	if security == "reality" {
		realitySettings := map[string]interface{}{
			"serverName":  proxy.SNI,
			"fingerprint": proxy.Fingerprint,
			"publicKey":   proxy.PublicKey,
		}
		if proxy.ShortID != "" {
			realitySettings["shortId"] = proxy.ShortID
		}
		ss["realitySettings"] = realitySettings
	}

	switch network {
	case "tcp":
		if proxy.HeaderType != "" && proxy.HeaderType != "none" {
			header := map[string]interface{}{"type": proxy.HeaderType}
			if proxy.HeaderType == "http" {
				header["request"] = map[string]interface{}{
					"path":    []string{proxy.Path},
					"headers": map[string]interface{}{"Host": []string{proxy.Host}},
				}
			}
			ss["tcpSettings"] = map[string]interface{}{"header": header}
		}

	case "ws":
		wsSettings := map[string]interface{}{"path": proxy.Path}
		if proxy.Host != "" {
			wsSettings["headers"] = map[string]interface{}{"Host": proxy.Host}
		}
		ss["wsSettings"] = wsSettings

	case "grpc":
		ss["grpcSettings"] = map[string]interface{}{
			"serviceName": proxy.GetServiceName(),
			"multiMode":   proxy.MultiMode,
		}

	case "kcp", "mkcp":
		kcpSettings := map[string]interface{}{}
		if isValidKCPMTU(proxy.KCPMTU) {
			kcpSettings["mtu"] = proxy.KCPMTU
		}
		ss["kcpSettings"] = kcpSettings

	case "http", "h2":
		httpSettings := map[string]interface{}{"path": proxy.Path}
		if proxy.Host != "" {
			httpSettings["host"] = strings.Split(proxy.Host, ",")
		}
		ss["httpSettings"] = httpSettings

	case "httpupgrade":
		httpUpgradeSettings := map[string]interface{}{"path": proxy.Path}
		if proxy.Host != "" {
			httpUpgradeSettings["host"] = proxy.Host
		}
		ss["httpupgradeSettings"] = httpUpgradeSettings

	case "splithttp":
		if proxy.RawXhttpSettings != "" {
			var rawSettings map[string]interface{}
			if err := json.Unmarshal([]byte(proxy.RawXhttpSettings), &rawSettings); err == nil {
				ss["splithttpSettings"] = rawSettings
			}
		} else {
			splitSettings := map[string]interface{}{"path": proxy.Path}
			if proxy.Host != "" {
				splitSettings["host"] = proxy.Host
			}
			if proxy.Mode != "" {
				splitSettings["mode"] = proxy.Mode
			}
			ss["splithttpSettings"] = splitSettings
		}

	case "xhttp":
		if proxy.RawXhttpSettings != "" {
			var rawSettings map[string]interface{}
			if err := json.Unmarshal([]byte(proxy.RawXhttpSettings), &rawSettings); err == nil {
				ss["xhttpSettings"] = rawSettings
			}
		} else {
			xhttpSettings := map[string]interface{}{"path": proxy.Path}
			if proxy.Host != "" {
				xhttpSettings["host"] = proxy.Host
			}
			if proxy.Mode != "" {
				xhttpSettings["mode"] = proxy.Mode
			}
			ss["xhttpSettings"] = xhttpSettings
		}
	}

	return ss
}

func (g *ConfigGenerator) generateRouting(proxies []*models.ProxyConfig) map[string]interface{} {
	var rules []map[string]interface{}

	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"protocol":    []string{"dns"},
		"outboundTag": "dns-out",
	})

	for _, proxy := range proxies {
		inboundTag := fmt.Sprintf("%s_%s_%d_Inbound", proxy.Name, proxy.Protocol, proxy.Index)
		outboundTag := fmt.Sprintf("%s_%d", proxy.Name, proxy.Index)

		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{inboundTag},
			"outboundTag": outboundTag,
		})
	}

	return map[string]interface{}{
		"domainStrategy": "AsIs",
		"rules":          rules,
	}
}
