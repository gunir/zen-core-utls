package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ZenPrivacy/zen-core/internal/redacted"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// certGenerator is an interface capable of generating certificates for the proxy.
type certGenerator interface {
	GetCertificate(host string) (*tls.Certificate, error)
}

// filter is an interface capable of filtering HTTP requests.
type filter interface {
	HandleRequest(*http.Request) (*http.Response, error)
	HandleResponse(*http.Request, *http.Response) error
}

// Proxy is a forward HTTP/HTTPS proxy that can filter requests.
type Proxy struct {
	filter             filter
	certGenerator      certGenerator
	port               int
	server             *http.Server
	requestTransport   http.RoundTripper
	requestClient      *http.Client
	netDialer          *net.Dialer
	transparentHosts   []string
	transparentHostsMu sync.RWMutex
}

// --- UTLSTransport (per-request uTLS + H2/H1 handling) ---
//
// This RoundTripper performs a uTLS handshake for each request and then
// issues the request either using an http2.ClientConn (if ALPN h2) or
// by writing the request directly over the uTLS connection (HTTP/1.1).
// The response body is wrapped so closing it closes the underlying connection.
type UTLSTransport struct {
	Fingerprint utls.ClientHelloID
	Dialer      *net.Dialer
	// Timeout for dial/handshake (optional)
	DialTimeout time.Duration
}

type responseBodyCloser struct {
	io.ReadCloser
	conn net.Conn
}

func (r *responseBodyCloser) Close() error {
	_ = r.ReadCloser.Close()
	return r.conn.Close()
}

func (t *UTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid mutating caller's object
	ctx := req.Context()
	req2 := req.Clone(ctx)
	// Clear RequestURI so http.Client accepts it (it must be origin-form)
	req2.RequestURI = ""

	// Hostname for TLS/SNI
	host := req.URL.Hostname()
	if host == "" {
		// fallback: use Host field if URL.Hostname empty
		host = req.Host
	}

	// Build address for TCP dial
	addr := net.JoinHostPort(host, "443")

	// Dial TCP
	dialer := t.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 15 * time.Second}
	}
	var rawConn net.Conn
	var err error
	if t.DialTimeout > 0 {
		dctx, cancel := context.WithTimeout(ctx, t.DialTimeout)
		defer cancel()
		rawConn, err = dialer.DialContext(dctx, "tcp", addr)
	} else {
		rawConn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	// Prepare uTLS config
	cfg := &utls.Config{
		ServerName: host,
		MinVersion: utls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	// Build uTLS client with requested fingerprint
	uconn := utls.UClient(rawConn, cfg, t.Fingerprint)

	// Ensure ALPN extension present (some fingerprints override it), then rebuild
	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("build handshake state 1: %w", err)
	}
	found := false
	for i, ext := range uconn.Extensions {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			uconn.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
			found = true
			break
		}
	}
	if !found {
		uconn.Extensions = append(uconn.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}})
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("build handshake state 2: %w", err)
	}

	// Handshake (context-aware if available)
	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	cs := uconn.ConnectionState()
	log.Printf("[uTLS] %s negotiated ALPN=%q tlsver=0x%x\n", host, cs.NegotiatedProtocol, cs.Version)

	// If HTTP/2 negotiated -> build http2.ClientConn over the existing uconn
	if cs.NegotiatedProtocol == "h2" {
		t2 := &http2.Transport{
			// Let NewClientConn use the existing TLS connection
			AllowHTTP: false,
		}
		cc, err := t2.NewClientConn(uconn)
		if err != nil {
			uconn.Close()
			return nil, fmt.Errorf("http2 NewClientConn: %w", err)
		}

		// Ensure the request is origin-form: URL should already be set appropriate by caller.
		// Use cc.RoundTrip to perform the request over this connection.
		resp, err := cc.RoundTrip(req2)
		if err != nil {
			_ = cc.Close()
			return nil, err
		}

		// Wrap body so closing it also closes underlying connection
		resp.Body = &responseBodyCloser{ReadCloser: resp.Body, conn: uconn}
		return resp, nil
	}

	// Otherwise: HTTP/1.1 path — write request and read response directly on uconn
	// Ensure Host header is set
	if req2.Host == "" {
		req2.Host = req2.URL.Host
	}
	if err := req2.Write(uconn); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("write request: %w", err)
	}
	br := bufio.NewReader(uconn)
	resp, err := http.ReadResponse(br, req2)
	if err != nil {
		uconn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	resp.Body = &responseBodyCloser{ReadCloser: resp.Body, conn: uconn}
	return resp, nil
}

func NewProxy(filter filter, certGenerator certGenerator, port int) (*Proxy, error) {
	if filter == nil {
		return nil, errors.New("filter is nil")
	}
	if certGenerator == nil {
		return nil, errors.New("certGenerator is nil")
	}

	p := &Proxy{
		filter:        filter,
		certGenerator: certGenerator,
		port:          port,
	}

	p.netDialer = &net.Dialer{
		// Such high values are set to avoid timeouts on slow connections.
		Timeout:   60 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Keep a default requestTransport for non-HTTPS short-circuit uses (not used for MITM).
	p.requestTransport = &http.Transport{
		Dial:                p.netDialer.Dial,
		TLSHandshakeTimeout: 20 * time.Second,
	}

	// Use UTLSTransport for all client requests so uTLS fingerprint is used.
	p.requestClient = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &UTLSTransport{
			Fingerprint: utls.HelloFirefox_120, // change if you want another fingerprint
			Dialer:      p.netDialer,
			DialTimeout: 15 * time.Second,
		},
		// Let the client handle any redirects.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return p, nil
}

// Start starts the proxy on the given address.
//
// If Proxy was configured with a port of 0, the actual port will be returned.
func (p *Proxy) Start() (int, error) {
	p.server = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", "127.0.0.1", p.port))
	if err != nil {
		return 0, fmt.Errorf("listen: %v", err)
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	log.Printf("proxy listening on port %d", actualPort)

	go func() {
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("serve: %v", err)
		}
	}()

	return actualPort, nil
}

// Stop stops the proxy.
func (p *Proxy) Stop() error {
	if err := p.shutdownServer(); err != nil {
		return fmt.Errorf("shut down server: %v", err)
	}

	return nil
}

func (p *Proxy) shutdownServer() error {
	if p.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := p.server.Shutdown(ctx); err != nil {
		// As per documentation:
		// Shutdown does not attempt to close nor wait for hijacked connections such as WebSockets. The caller of Shutdown should separately notify such long-lived connections of shutdown and wait for them to close, if desired. See RegisterOnShutdown for a way to register shutdown notification functions.
		// TODO: implement websocket shutdown
		return fmt.Errorf("server shutdown: %w", err)
	}

	return nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.proxyConnect(w, r)
	} else {
		p.proxyHTTP(w, r)
	}
}

// proxyHTTP proxies the HTTP request to the remote server.
func (p *Proxy) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	filterResp, err := p.filter.HandleRequest(r)
	if err != nil {
		log.Printf("error handling request for %q: %v", redacted.Redacted(r.URL), err)
	}

	if filterResp != nil {
		filterResp.Write(w)
		return
	}

	if isWS(r) {
		// should we remove hop-by-hop headers here?
		p.proxyWebsocket(w, r)
		return
	}
	log.Printf("[uTLS ProxyHTTP r] %s", r)

	r.RequestURI = ""

	removeHopHeaders(r.Header)

	resp, err := p.requestClient.Do(r)
	if err != nil {
		log.Printf("error making request: %v", redacted.Redacted(err)) // The error might contain information about the hostname we are connecting to.
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	log.Printf("[uTLS ProxyHTTP] %s", resp.Header)
	if err := p.filter.HandleResponse(r, resp); err != nil {
		log.Printf("error handling response by filter: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyConnect proxies the initial CONNECT and subsequent data between the
// client and the remote server.
func (p *Proxy) proxyConnect(w http.ResponseWriter, connReq *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Fatal("http server does not support hijacking")
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		log.Printf("hijacking connection(%s): %v", redacted.Redacted(connReq.Host), err)
		return
	}
	defer clientConn.Close()

	host, _, err := net.SplitHostPort(connReq.Host)
	if err != nil {
		log.Printf("splitting host and port(%s): %v", redacted.Redacted(connReq.Host), err)
		return
	}

	if !p.shouldMITM(host) || net.ParseIP(host) != nil {
		// TODO: implement upstream certificate sniffing
		// https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/#complication-1-whats-the-remote-hostname
		p.tunnel(clientConn, connReq)
		return
	}

	tlsCert, err := p.certGenerator.GetCertificate(host)
	if err != nil {
		log.Printf("getting certificate(%s): %v", redacted.Redacted(connReq.Host), err)
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		log.Printf("writing 200 OK to client(%s): %v", redacted.Redacted(connReq.Host), err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()
	connReader := bufio.NewReader(tlsConn)

	// Read requests in a loop to allow for HTTP connection reuse.
	// https://en.wikipedia.org/wiki/HTTP_persistent_connection
	for {
		req, err := http.ReadRequest(connReader)
		if err != nil {
			if err != io.EOF {

				msg := err.Error()
				if strings.Contains(msg, "tls: ") {
					log.Printf("adding %s to ignored hosts", redacted.Redacted(host))
					p.addTransparentHost(host)
				}

				// The following errors occur when the underlying clientConn is closed.
				// This usually happens during normal request/response flow when the client
				// decides it no longer needs the connection to the host.
				// To avoid excessive noise in the logs, we suppress these messages.
				if !strings.HasSuffix(msg, "connection reset by peer") && !strings.HasSuffix(msg, "An existing connection was forcibly closed by the remote host.") {
					log.Printf("reading request(%s): %v", redacted.Redacted(connReq.Host), err)
				}
			}
			break
		}
		req.URL.Host = connReq.Host

		if isWS(req) {
			// Establish transparent flow, no hop-by-hop header removal required.
			p.proxyWebsocketTLS(req, tlsConfig, tlsConn)
			break
		}

		// A standard CONNECT proxy establishes a TCP connection to the requested destination and relays the stream between the client and server.
		// Here, we are MITM-ing the traffic and handling the request-response flow ourselves.
		// Since the client and server do not share a direct TCP connection in this setup, we must strip hop-by-hop headers.
		removeHopHeaders(req.Header)
		req.URL.Scheme = "https"

		filterResp, err := p.filter.HandleRequest(req)
		if err != nil {
			log.Printf("handling request for %q: %v", redacted.Redacted(req.URL), err)
		}
		if filterResp != nil {
			if _, err := io.Copy(io.Discard, req.Body); err != nil {
				log.Printf("discarding body for %q: %v", redacted.Redacted(req.URL), err)
				break
			}
			if err := req.Body.Close(); err != nil {
				log.Printf("closing body for %q: %v", redacted.Redacted(req.URL), err)
				break
			}
			if err := filterResp.Write(tlsConn); err != nil {
				log.Printf("writing filter response for %q: %v", redacted.Redacted(req.URL), err)
				break
			}

			if req.Close {
				break
			}
			continue
		}

		// Convert request to client-style (origin-form) so http.Client.Do accepts it.
		req.RequestURI = ""
		//req.URL.Scheme = "https"
		// url.Host may contain port; we want host only for URL.Host (client-friendly).
		req.URL.Host = host
		log.Printf("[uTLS ProxyConnect req] %s", req)

		resp, err := p.requestClient.Do(req)
		if err != nil {
			if strings.Contains(err.Error(), "tls: ") {
				log.Printf("adding %s to ignored hosts", redacted.Redacted(host))
				p.addTransparentHost(host)
			}

			log.Printf("roundtrip(%s): %v", redacted.Redacted(connReq.Host), err)
			// TODO: better error presentation
			response := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\n\r\n%s", err.Error())
			tlsConn.Write([]byte(response))
			break
		}
		/*
		// ----------------------------
		// FORCE DOWNSTREAM HTTP/1.1
		// ----------------------------
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1
		resp.Status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))

		// Clean H2-specific headers
		resp.Header.Del("Alt-Svc")
		resp.Header.Del("HTTP2-Settings")
		resp.Header.Del("Connection")
		resp.Header.Del("Upgrade")
		*/

		//FIX A: Ensure Content-Length is set
		if resp.Header.Get("Content-Length") == "" && resp.ContentLength >= 0 {
		    resp.Header.Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
		}
		// Ensure correct framing
		if resp.ContentLength == -1 {
		    resp.TransferEncoding = []string{"chunked"}
		}



		removeHopHeaders(resp.Header)
		log.Printf("[uTLS ProxyConnect] %s", resp)


		if err := p.filter.HandleResponse(req, resp); err != nil {
			log.Printf("error handling response by filter for %q: %v", redacted.Redacted(req.URL), err)
			if err := resp.Body.Close(); err != nil {
				log.Printf("closing body for %q: %v", redacted.Redacted(req.URL), err)
			}
			response := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\n\r\n%s", err.Error())
			tlsConn.Write([]byte(response))
			break
		}

		if err := resp.Write(tlsConn); err != nil {
			log.Printf("writing response(%q): %v", redacted.Redacted(connReq.Host), err)
			if err := resp.Body.Close(); err != nil {
				log.Printf("closing body(%q): %v", redacted.Redacted(connReq.Host), err)
			}
			break
		}

		/*
		// STREAM RESPONSE MANUALLY to tlsConn (safe against early client disconnect)
		// Write status line
		_, _ = fmt.Fprintf(tlsConn, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		// Write headers
		for k, vv := range resp.Header {
			for _, v := range vv {
				_, _ = fmt.Fprintf(tlsConn, "%s: %s\r\n", k, v)
			}
		}
		_, _ = fmt.Fprint(tlsConn, "\r\n")

		// Stream body in chunks; on client disconnect stop and cleanup.
		buf := make([]byte, 32*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				_, werr := tlsConn.Write(buf[:n])
				if werr != nil {
					if isCloseable(werr) || strings.Contains(werr.Error(), "broken pipe") {
						log.Printf("client disconnected early while writing to %s: %v", redacted.Redacted(connReq.Host), werr)
						break
					}
					log.Printf("write error while writing to %s: %v", redacted.Redacted(connReq.Host), werr)
					break
				}
			}
			if rerr != nil {
				if rerr != io.EOF {
					log.Printf("reading body(%s): %v", redacted.Redacted(connReq.Host), rerr)
				}
				break
			}
		}
		*/

		if err := resp.Body.Close(); err != nil {
			log.Printf("closing body(%q): %v", redacted.Redacted(connReq.Host), err)
		}

		if req.Close || resp.Close {
			break
		}
	}
}

// shouldMITM returns true if the host should be MITM'd.
func (p *Proxy) shouldMITM(host string) bool {
	p.transparentHostsMu.RLock()
	defer p.transparentHostsMu.RUnlock()

	for _, transparentHost := range p.transparentHosts {
		if host == transparentHost || strings.HasSuffix(host, "."+transparentHost) {
			return false
		}
	}

	return true
}

// addTransparentHost adds a host to the list of hosts that should be MITM'd.
func (p *Proxy) addTransparentHost(host string) {
	p.transparentHostsMu.Lock()
	defer p.transparentHostsMu.Unlock()

	p.transparentHosts = append(p.transparentHosts, host)
}

// tunnel tunnels the connection between the client and the remote server
// without inspecting the traffic.
func (p *Proxy) tunnel(w net.Conn, r *http.Request) {
	remoteConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("dialing remote(%s): %v", redacted.Redacted(r.Host), err)
		w.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remoteConn.Close()

	if _, err := w.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		log.Printf("writing 200 OK to client(%s): %v", redacted.Redacted(r.Host), err)
		return
	}

	linkBidirectionalTunnel(w, remoteConn)
}

func linkBidirectionalTunnel(src, dst io.ReadWriter) {
	doneC := make(chan struct{}, 2)
	go tunnelConn(src, dst, doneC)
	go tunnelConn(dst, src, doneC)
	<-doneC
	<-doneC
}

// tunnelConn tunnels the data between src and dst.
func tunnelConn(dst io.Writer, src io.Reader, done chan<- struct{}) {
	if _, err := io.Copy(dst, src); err != nil && !isCloseable(err) {
		log.Printf("copying: %v", err)
	}
	done <- struct{}{}
}

// isCloseable returns true if the error is one that indicates the connection
// can be closed.
func isCloseable(err error) (ok bool) {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	switch err {
	case io.EOF, io.ErrClosedPipe, io.ErrUnexpectedEOF:
		return true
	default:
		return false
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
// Note: this may be out of date, see RFC 7230 Section 6.1.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // spelling per https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}
