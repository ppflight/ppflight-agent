// Package exporter fetches and normalises a deliberately small, bounded subset
// of local Prometheus exporter metrics. It does not proxy arbitrary metrics.
package exporter

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

var errNonFiniteMetricValue = errors.New("metric value is not finite")

const (
	defaultMaxBody = int64(8 << 20)
	maxBody        = int64(32 << 20)
	maxLine        = 64 << 10
	maxSamples     = 200000
	maxLabels      = 32
)

type FetchConfig struct {
	URL          string
	Timeout      time.Duration
	MaxBodyBytes int64
}
type Sample struct {
	Name     string
	Labels   map[string]string
	Value    float64
	RawValue string
}

// Fetch reads a local /metrics endpoint and returns valid Prometheus samples.
// The endpoint host is deliberately restricted to loopback, including
// localhost; remote exporters must be collected by an agent installed there.
func Fetch(ctx context.Context, cfg FetchConfig) ([]Sample, error) {
	endpoint := cfg.URL
	if endpoint == "" {
		return nil, errors.New("exporter URL is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid exporter URL %q", endpoint)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("exporter URL must use HTTP or HTTPS")
	}
	if !loopback(u.Hostname()) {
		return nil, errors.New("exporter URL must target localhost")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	limit := cfg.MaxBodyBytes
	if limit <= 0 {
		limit = defaultMaxBody
	}
	if limit > maxBody {
		return nil, fmt.Errorf("exporter response limit exceeds %d bytes", maxBody)
	}
	client := &http.Client{Timeout: timeout, Transport: netpolicy.ApplyIPv4Only(&http.Transport{Proxy: nil})}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain; version=0.0.4")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch exporter: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exporter returned HTTP %d", resp.StatusCode)
	}
	return Parse(io.LimitReader(resp.Body, limit+1), limit)
}

func loopback(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil && ip.IsLoopback()
}

// Parse parses the Prometheus text exposition format needed by standard node
// exporter and smartctl_exporter. It rejects overlong lines, label explosions,
// malformed escaping, non-finite values and responses over the supplied limit.
func Parse(r io.Reader, bodyLimit int64) ([]Sample, error) {
	if bodyLimit <= 0 || bodyLimit > maxBody {
		return nil, errors.New("invalid exporter body limit")
	}
	counted := &countingReader{r: io.LimitReader(r, bodyLimit+1)}
	scanner := bufio.NewScanner(counted)
	scanner.Buffer(make([]byte, 4096), maxLine)
	var samples []Sample
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sample, err := parseLine(line)
		// NaN and +/-Inf are valid Prometheus exposition values and are emitted
		// by real node_exporter/smartctl_exporter installations when one sensor
		// or kernel counter is unavailable.  They cannot be represented in our
		// JSON wire contract, but one unavailable sample must not discard every
		// other valid interface, disk and SMART sample from the same response.
		if errors.Is(err, errNonFiniteMetricValue) {
			continue
		}
		if err != nil {
			return nil, err
		}
		samples = append(samples, sample)
		if len(samples) > maxSamples {
			return nil, fmt.Errorf("exporter has more than %d samples", maxSamples)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse exporter metrics: %w", err)
	}
	if counted.n > bodyLimit {
		return nil, fmt.Errorf("exporter response exceeds %d bytes", bodyLimit)
	}
	return samples, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

func parseLine(line string) (Sample, error) {
	first := sampleValueSeparator(line)
	if first < 1 {
		return Sample{}, errors.New("metric sample has no value")
	}
	series, rest := line[:first], strings.TrimSpace(line[first:])
	fields := strings.Fields(rest)
	if len(fields) < 1 || len(fields) > 2 {
		return Sample{}, errors.New("invalid metric sample value")
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return Sample{}, errNonFiniteMetricValue
	}
	name, labels, err := parseSeries(series)
	if err != nil {
		return Sample{}, err
	}
	return Sample{Name: name, Labels: labels, Value: value, RawValue: fields[0]}, nil
}

// sampleValueSeparator finds the first whitespace outside a Prometheus label
// set. Real exporters routinely include spaces inside quoted labels (kernel
// versions, disk model names, mountpoints). strings.IndexAny would split those
// valid series names in the middle and make the entire exporter unavailable.
func sampleValueSeparator(line string) int {
	inLabels, inQuote, escaped := false, false, false
	for index := 0; index < len(line); index++ {
		character := line[index]
		if inQuote {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
				continue
			}
			if character == '"' {
				inQuote = false
			}
			continue
		}
		switch character {
		case '{':
			inLabels = true
		case '}':
			inLabels = false
		case '"':
			if inLabels {
				inQuote = true
			}
		case ' ', '\t':
			if !inLabels {
				return index
			}
		}
	}
	return -1
}
func parseSeries(series string) (string, map[string]string, error) {
	open := strings.IndexByte(series, '{')
	if open < 0 {
		if !metricName(series) {
			return "", nil, errors.New("invalid metric name")
		}
		return series, nil, nil
	}
	if !strings.HasSuffix(series, "}") || !metricName(series[:open]) {
		return "", nil, errors.New("invalid labelled metric")
	}
	labels, err := parseLabels(series[open+1 : len(series)-1])
	if err != nil {
		return "", nil, err
	}
	return series[:open], labels, nil
}
func metricName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || r == ':' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
func parseLabels(s string) (map[string]string, error) {
	if s == "" {
		return map[string]string{}, nil
	}
	result := map[string]string{}
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq < 1 || !metricName(s[:eq]) || eq+1 >= len(s) || s[eq+1] != '"' {
			return nil, errors.New("invalid metric label")
		}
		key := s[:eq]
		s = s[eq+2:]
		var b strings.Builder
		closed := false
		for len(s) > 0 {
			ch := s[0]
			s = s[1:]
			if ch == '"' {
				closed = true
				break
			}
			if ch == '\\' {
				if len(s) == 0 {
					return nil, errors.New("unfinished label escape")
				}
				esc := s[0]
				s = s[1:]
				switch esc {
				case '\\', '"':
					b.WriteByte(esc)
				case 'n':
					b.WriteByte('\n')
				default:
					return nil, errors.New("invalid label escape")
				}
			} else {
				b.WriteByte(ch)
			}
			if b.Len() > 4096 {
				return nil, errors.New("label value too large")
			}
		}
		if !closed {
			return nil, errors.New("unterminated metric label")
		}
		if _, duplicate := result[key]; duplicate {
			return nil, errors.New("duplicate metric label")
		}
		result[key] = b.String()
		if len(result) > maxLabels {
			return nil, errors.New("too many metric labels")
		}
		if s == "" {
			break
		}
		if s[0] != ',' {
			return nil, errors.New("invalid label separator")
		}
		s = s[1:]
	}
	return result, nil
}
