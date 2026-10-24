package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// settings are the resolved defaults for the global flags. Precedence:
// command-line flag > environment > selected profile > built-in default.
type settings struct {
	endpoint    string
	region      string
	accessKey   string
	secretKey   string
	coordinator string
	timeout     time.Duration
	profileName string
	configPath  string
	// endpointExplicit records whether the S3 endpoint came from configuration
	// rather than the built-in default. `fass health` uses it to decide whether
	// checking the gateway makes sense.
	endpointExplicit bool
}

// built-in defaults match the dev deployment (docs/08-operations.md).
const (
	defaultEndpoint    = "http://127.0.0.1:8080"
	defaultRegion      = "eu-west-1"
	defaultCoordinator = "http://127.0.0.1:7000"
	defaultTimeout     = 60 * time.Second
)

// configFile is a tiny INI-like format: `[profile]` sections with key = value
// lines. Comments start with # or ;. It is deliberately not YAML/TOML: the
// command must stay dependency-free and the file is trivial to write by hand.
type configFile map[string]map[string]string

// loadConfigFile parses path. A missing file is not an error (an operator may
// run entirely on flags/env); an unreadable explicit file is.
func loadConfigFile(path string, explicit bool) (configFile, error) {
	cfg := configFile{}
	if path == "" {
		return cfg, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			return cfg, nil
		}
		return nil, usagef("cannot read config %s: %v", path, err)
	}
	defer f.Close()

	section := "default"
	cfg[section] = map[string]string{}
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "" {
				return nil, usagef("%s:%d: empty section name", path, lineNo)
			}
			if cfg[section] == nil {
				cfg[section] = map[string]string{}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, usagef("%s:%d: expected key = value", path, lineNo)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		// Allow simple quoted values: endpoint = "http://..."
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		if k == "" {
			return nil, usagef("%s:%d: empty key", path, lineNo)
		}
		cfg[section][k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, usagef("read config %s: %v", path, err)
	}
	return cfg, nil
}

// resolveSettings combines the selected profile with environment variables.
func resolveSettings(profileFlag, configPathFlag string) (settings, error) {
	configPath := configPathFlag
	explicitConfig := configPath != ""
	if configPath == "" {
		configPath = envString("FASS_CONFIG")
		explicitConfig = configPath != ""
	}
	if configPath == "" {
		configPath = defaultConfigPath()
	}

	profileName := profileFlag
	if profileName == "" {
		profileName = envString("FASS_PROFILE")
	}
	if profileName == "" {
		profileName = "default"
	}

	cfg, err := loadConfigFile(configPath, explicitConfig)
	if err != nil {
		return settings{}, err
	}

	section := cfg[profileName]
	if section == nil {
		if profileName != "default" {
			return settings{}, usagef("profile %q not found in %s", profileName, configPath)
		}
		section = map[string]string{}
	}

	s := settings{
		endpoint:    firstNonEmpty(section["endpoint"], section["url"]),
		region:      firstNonEmpty(section["region"]),
		accessKey:   firstNonEmpty(section["access_key"], section["access_key_id"], section["accesskey"]),
		secretKey:   firstNonEmpty(section["secret_key"], section["secret_access_key"], section["secret"]),
		coordinator: firstNonEmpty(section["coordinator"], section["coordinator_url"], section["admin_endpoint"]),
		timeout:     defaultTimeout,
		profileName: profileName,
		configPath:  configPath,
	}
	if raw := firstNonEmpty(section["timeout"]); raw != "" {
		d, derr := time.ParseDuration(raw)
		if derr != nil || d <= 0 {
			return settings{}, usagef("profile %q: invalid timeout %q", profileName, raw)
		}
		s.timeout = d
	}

	// Environment beats the profile (flags beat both, because they are parsed
	// into these same fields afterwards).
	s.endpoint = firstNonEmpty(envString("FASS_ENDPOINT"), envString("FASS_S3_ENDPOINT"), s.endpoint)
	s.region = firstNonEmpty(envString("FASS_REGION"), envString("AWS_REGION"), envString("AWS_DEFAULT_REGION"), s.region)
	s.accessKey = firstNonEmpty(envString("FASS_ACCESS_KEY_ID"), envString("FASS_ACCESS_KEY"), envString("AWS_ACCESS_KEY_ID"), s.accessKey)
	s.secretKey = firstNonEmpty(envString("FASS_SECRET_ACCESS_KEY"), envString("FASS_SECRET_KEY"), envString("FASS_SECRET"), envString("AWS_SECRET_ACCESS_KEY"), s.secretKey)
	s.coordinator = firstNonEmpty(envString("FASS_COORDINATOR_URL"), envString("FASS_COORDINATOR"), s.coordinator)
	if raw := envString("FASS_TIMEOUT"); raw != "" {
		d, derr := time.ParseDuration(raw)
		if derr != nil || d <= 0 {
			return settings{}, usagef("invalid FASS_TIMEOUT %q", raw)
		}
		s.timeout = d
	}

	s.endpointExplicit = s.endpoint != ""
	s.endpoint = firstNonEmpty(s.endpoint, defaultEndpoint)
	s.region = firstNonEmpty(s.region, defaultRegion)
	s.coordinator = firstNonEmpty(s.coordinator, defaultCoordinator)
	// A trailing slash makes every URL join double up.
	s.endpoint = strings.TrimRight(s.endpoint, "/")
	s.coordinator = strings.TrimRight(s.coordinator, "/")
	return s, nil
}

func envString(key string) string { return strings.TrimSpace(os.Getenv(key)) }

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// validateCoordinatorURL is a cheap sanity check that turns a typo into a user
// error instead of a mysterious network failure.
func validateCoordinatorURL(raw string) error {
	if raw == "" {
		return usagef("no coordinator URL configured (use --coordinator or FASS_COORDINATOR_URL)")
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return usagef("coordinator URL %q must start with http:// or https://", raw)
	}
	return nil
}

// String renders settings without secrets (used by tests and --debug paths).
func (s settings) String() string {
	return fmt.Sprintf("endpoint=%s region=%s coordinator=%s profile=%s config=%s", s.endpoint, s.region, s.coordinator, s.profileName, s.configPath)
}
