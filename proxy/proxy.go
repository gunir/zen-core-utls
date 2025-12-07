package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ZenPrivacy/zen-core/internal/redacted"
	//utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	utls "github.com/bogdanfinn/utls"
	"github.com/bogdanfinn/utls/dicttls"
)

// H2Fingerprint defines the specific HTTP/2 parameters to mimic a browser.
type H2Fingerprint struct {
	Settings              []http2.Setting
	WindowUpdateIncrement uint32
	PseudoHeaderOrder     []string
	HeaderPriority        []string // Order of standard headers
	PriorityParam         http2.PriorityParam
}

var Firefox135TLSFingerprint = utls.ClientHelloSpec{
				CipherSuites: []uint16{
					utls.TLS_AES_128_GCM_SHA256,
					utls.TLS_CHACHA20_POLY1305_SHA256,
					utls.TLS_AES_256_GCM_SHA384,
					utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					utls.TLS_RSA_WITH_AES_128_CBC_SHA,
					utls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					utls.CompressionNone,
				},
				Extensions: []utls.TLSExtension{
					&utls.SNIExtension{},
					&utls.ExtendedMasterSecretExtension{},
					&utls.RenegotiationInfoExtension{
						Renegotiation: utls.RenegotiateOnceAsClient,
					},
					&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
						utls.X25519MLKEM768,
						utls.X25519,
						utls.CurveP256,
						utls.CurveP384,
						utls.CurveP521,
						utls.FAKEFFDHE2048,
						utls.FAKEFFDHE3072,
					}},
					&utls.SupportedPointsExtension{SupportedPoints: []byte{
						utls.PointFormatUncompressed,
					}},
					&utls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&utls.StatusRequestExtension{},
					&utls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
						utls.ECDSAWithP256AndSHA256,
						utls.ECDSAWithP384AndSHA384,
						utls.ECDSAWithP521AndSHA512,
						utls.ECDSAWithSHA1,
					}},
					&utls.SCTExtension{},
					&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
						{Group: utls.X25519MLKEM768},
						{Group: utls.X25519},
						{Group: utls.CurveP256},
					}},
					&utls.SupportedVersionsExtension{Versions: []uint16{
						utls.VersionTLS13,
						utls.VersionTLS12,
					}},
					&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
						utls.ECDSAWithP256AndSHA256,
						utls.ECDSAWithP384AndSHA384,
						utls.ECDSAWithP521AndSHA512,
						utls.PSSWithSHA256,
						utls.PSSWithSHA384,
						utls.PSSWithSHA512,
						utls.PKCS1WithSHA256,
						utls.PKCS1WithSHA384,
						utls.PKCS1WithSHA512,
						utls.ECDSAWithSHA1,
						utls.PKCS1WithSHA1,
					}},
					&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
						utls.CertCompressionZlib,
						utls.CertCompressionBrotli,
						utls.CertCompressionZstd,
					}},
					&utls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_256_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_CHACHA20_POLY1305,
							},
						},
						CandidatePayloadLens: []uint16{128, 223}, // +16: 144, 239
					},
				},
			}

//var Firefox135TLSFingerprintID = utls.ClientHelloID{Firefox135TLSFingerprint, "135", nil, nil}
// Firefox135H2Fingerprint based on "Firefox_135" from contributed_browser_profiles.go
var Firefox135H2Fingerprint = H2Fingerprint{
	Settings: []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 131072},
		{ID: http2.SettingMaxFrameSize, Val: 16384},
	},
	WindowUpdateIncrement: 12517377, // 12.5MB
	PseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	HeaderPriority: []string{
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
		"referer",
		"upgrade-insecure-requests",
		"sec-fetch-dest",
		"sec-fetch-mode",
		"sec-fetch-site",
		"sec-fetch-user",
		"te",
	},
	PriorityParam: http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    41, // Wire value for weight 42
	},
}

// Chrome131H2Fingerprint based on "Chrome_131" from contributed_browser_profiles.go
var Chrome131H2Fingerprint = H2Fingerprint{
	Settings: []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456}, // 6MB
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	},
	WindowUpdateIncrement: 15663105, // ~15.6MB
	PseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	// Chrome Header Order (Approximated as it's not in the uploaded file)
	HeaderPriority: []string{
		"host",
		"connection",
		"content-length",
		"sec-ch-ua",
		"sec-ch-ua-platform",
		"sec-ch-ua-mobile",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"accept-language",
		"cookie",
	},
	PriorityParam: http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    255, // Chrome uses default weight (256 - 1)
	},
}

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
type UTLSTransport struct {
	Fingerprint   utls.ClientHelloID
	H2Fingerprint H2Fingerprint // HTTP/2 specific fingerprint configuration
	Dialer        *net.Dialer
	DialTimeout   time.Duration
}

type responseBodyCloser struct {
	io.ReadCloser
	conn net.Conn
}

func (r *responseBodyCloser) Close() error {
	_ = r.ReadCloser.Close()
	return r.conn.Close()
}

func debugExtensions(exts []utls.TLSExtension) {
	log.Printf("[DEBUG] Current Extensions List (%d total):", len(exts))
	for i, ext := range exts {
		// We use fmt.Sprintf to inspect the type, as utls extension IDs aren't always public
		log.Printf("  [%d] Type: %T", i, ext)
	}
}

// createFirefox135Spec generates a FRESH, thread-safe copy of the spec.
// We use this function instead of a global variable to prevent race conditions
// on mutable fields like KeyShares.
func createFirefox135Spec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			utls.CompressionNone,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{
				Renegotiation: utls.RenegotiateOnceAsClient,
			},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
				utls.FAKEFFDHE2048,
				utls.FAKEFFDHE3072,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{
				utls.PointFormatUncompressed,
			}},
			&utls.ALPNExtension{AlpnProtocols: []string{
				"h2",
				"http/1.1",
			}},
			&utls.StatusRequestExtension{},
			&utls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.ECDSAWithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
				{Group: utls.CurveP256},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
				utls.CertCompressionBrotli,
				utls.CertCompressionZstd,
			}},
			&utls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
					{
						KdfId:  dicttls.HKDF_SHA256,
						AeadId: dicttls.AEAD_AES_128_GCM,
					},
					{
						KdfId:  dicttls.HKDF_SHA256,
						AeadId: dicttls.AEAD_AES_256_GCM,
					},
					{
						KdfId:  dicttls.HKDF_SHA256,
						AeadId: dicttls.AEAD_CHACHA20_POLY1305,
					},
				},
				CandidatePayloadLens: []uint16{128, 223}, // +16: 144, 239
			},
		},
	}
}

func (t *UTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	req2 := req.Clone(ctx)
	req2.RequestURI = ""

	host := req.URL.Hostname()
	if host == "" {
		host = req.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	addr := net.JoinHostPort(host, "443")
	log.Printf("[DEBUG] Dialing %s...", addr)

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

	// Prepare Config
	cfg := &utls.Config{
		ServerName: host,
		MinVersion: utls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	// 1. Create UClient
	uconn := utls.UClient(rawConn, cfg, utls.HelloCustom, false, false, false)

	// 2. Define the Spec INSIDE the function (Critical Fix)
	// This ensures every connection gets its own unique pointers.
	spec := createFirefox135Spec()

	// 3. Apply the LOCAL spec
	if err := uconn.ApplyPreset(spec); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("ApplyPreset failed: %w", err)
	}

	// 4. Handshake
	if err := uconn.HandshakeContext(ctx); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	log.Printf("[DEBUG] Handshake Success! Proto: %s", uconn.ConnectionState().NegotiatedProtocol)

	// H2 Handling
	cs := uconn.ConnectionState()
	if cs.NegotiatedProtocol == "h2" {
		return roundTripHTTP2Manual(req2, uconn, t.H2Fingerprint)
	}

	// HTTP/1.1 Fallback
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

// roundTripHTTP2Manual implements HTTP/2 with a customizable fingerprint
func roundTripHTTP2Manual(req *http.Request, conn net.Conn, fp H2Fingerprint) (*http.Response, error) {
	log.Printf("[H2-DEBUG] Starting manual H2 roundtrip for %s", req.URL)
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil) // Decoder for incoming headers

	var writeMu sync.Mutex

	// 1. Send Preface
	log.Printf("[H2-DEBUG] Sending Preface")
	writeMu.Lock()
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		writeMu.Unlock()
		conn.Close()
		return nil, fmt.Errorf("write preface: %w", err)
	}
	writeMu.Unlock()

	// 2. Send Settings (From Fingerprint)
	log.Printf("[H2-DEBUG] Sending Settings: %v", fp.Settings)
	writeMu.Lock()
	if err := framer.WriteSettings(fp.Settings...); err != nil {
		writeMu.Unlock()
		conn.Close()
		return nil, fmt.Errorf("write settings: %w", err)
	}
	writeMu.Unlock()

	// 3. Send Window Update (From Fingerprint)
	if fp.WindowUpdateIncrement > 0 {
		log.Printf("[H2-DEBUG] Sending Window Update: %d", fp.WindowUpdateIncrement)
		writeMu.Lock()
		if err := framer.WriteWindowUpdate(0, fp.WindowUpdateIncrement); err != nil {
			writeMu.Unlock()
			conn.Close()
			return nil, fmt.Errorf("write window update: %w", err)
		}
		writeMu.Unlock()
	}

	// Prepare to read response
	pr, pw := io.Pipe()
	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)
	readLoopDone := make(chan struct{})

	go func() {
		defer close(readLoopDone)
		defer conn.Close()
		defer pw.Close()

		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				if err != io.EOF {
					log.Printf("[H2-DEBUG] ReadFrame error: %v", err)
					select {
					case errChan <- err:
					default:
					}
				} else {
					log.Printf("[H2-DEBUG] ReadFrame EOF")
				}
				return
			}

			switch f := frame.(type) {
			case *http2.SettingsFrame:
				log.Printf("[H2-DEBUG] Received SETTINGS flags=%v", f.Flags)
				if f.IsAck() {
					continue
				}
				// Reply to server settings
				writeMu.Lock()
				err := framer.WriteSettingsAck()
				writeMu.Unlock()
				if err != nil {
					return
				}

			case *http2.MetaHeadersFrame:
				log.Printf("[H2-DEBUG] Received MetaHeadersFrame stream=%d endStream=%v", f.StreamID, f.StreamEnded())

				decodedHeaders := f.Fields
				res := &http.Response{
					Proto:      "HTTP/2.0",
					ProtoMajor: 2,
					ProtoMinor: 0,
					Header:     make(http.Header),
					Body:       pr,
					Request:    req,
				}

				for _, h := range decodedHeaders {
					switch h.Name {
					case ":status":
						code, _ := strconv.Atoi(h.Value)
						res.StatusCode = code
						res.Status = h.Value + " " + http.StatusText(code)
					default:
						if !strings.HasPrefix(h.Name, ":") {
							res.Header.Add(h.Name, h.Value)
						}
					}
				}

				if cl := res.Header.Get("Content-Length"); cl != "" {
					res.ContentLength, _ = strconv.ParseInt(cl, 10, 64)
				} else {
					res.ContentLength = -1
				}

				respChan <- res

				if f.StreamEnded() {
					return
				}

			case *http2.DataFrame:
				if f.StreamID != 3 {
					continue
				}
				if _, err := pw.Write(f.Data()); err != nil {
					return
				}
				if f.StreamEnded() {
					return
				}

			case *http2.GoAwayFrame:
				select {
				case errChan <- fmt.Errorf("received GOAWAY: ErrCode=%v DebugData=%q", f.ErrCode, f.DebugData()):
				default:
				}
				return
			case *http2.RSTStreamFrame:
				if f.StreamID == 3 {
					select {
					case errChan <- fmt.Errorf("stream 3 reset: ErrCode=%v", f.ErrCode):
					default:
					}
					return
				}
			}
		}
	}()

	// 4. Send Headers
	streamID := uint32(3)
	var headerBlock bytes.Buffer
	encoder := hpack.NewEncoder(&headerBlock)

	// FIX START: Use EscapedPath() or RawPath to preserve %xx encoding
    path := req.URL.EscapedPath()
    if path == "" {
        // Fallback if EscapedPath is empty (rare, but good for safety)
        path = req.URL.Path
    }
    if path == "" {
        path = "/"
    }
    // FIX END
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}

	authority := req.Host
	if authority == "" {
		authority = req.URL.Host
	}

	// Pseudo-Headers (Based on Fingerprint Order)
	// Default fallbacks if empty to prevent breakage
	pseudoOrder := fp.PseudoHeaderOrder
	if len(pseudoOrder) == 0 {
		pseudoOrder = []string{":method", ":path", ":authority", ":scheme"}
	}

	for _, k := range pseudoOrder {
		switch k {
		case ":method":
			encoder.WriteField(hpack.HeaderField{Name: ":method", Value: req.Method})
		case ":path":
			encoder.WriteField(hpack.HeaderField{Name: ":path", Value: path})
		case ":authority":
			encoder.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
		case ":scheme":
			encoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		}
	}

	// Regular Headers (Based on Fingerprint Order)
	writtenHeaders := make(map[string]bool)

	for _, k := range fp.HeaderPriority {
		if vals, ok := req.Header[http.CanonicalHeaderKey(k)]; ok {
			for _, v := range vals {
				encoder.WriteField(hpack.HeaderField{Name: k, Value: v})
			}
			writtenHeaders[k] = true
		}
	}
	/*
	// [FIX] Explicitly add Content-Length if missing from Header map
    if req.ContentLength > 0 && req.Header.Get("Content-Length") == "" {
        encoder.WriteField(hpack.HeaderField{
            Name:  "content-length",
            Value: strconv.FormatInt(req.ContentLength, 10),
        })
    }
    */
	// Write remaining headers
	for k, vv := range req.Header {
		lowerK := strings.ToLower(k)
        log.Printf("[H2-FRAME] Writing Header: %s", lowerK) 
		if writtenHeaders[lowerK] {
			continue
		}
		if lowerK == "host" || lowerK == "transfer-encoding" || lowerK == "connection" || lowerK == "upgrade" || lowerK == "priority" || lowerK == "http2-settings" {
			continue
		}
		for _, v := range vv {
			encoder.WriteField(hpack.HeaderField{Name: lowerK, Value: v})
		}
	}

	// Explicitly add Priority Header last if it's the custom H2 header
	log.Printf("[H2-DEBUG] Adding Header: priority = u=0, i")
	encoder.WriteField(hpack.HeaderField{Name: "priority", Value: "u=0, i"})
	encoder.WriteField(hpack.HeaderField{Name: "te", Value: "trailers"})

	log.Printf("[H2-DEBUG] Writing Headers Frame stream=%d priority=%v", streamID, fp.PriorityParam)
	writeMu.Lock()
	err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headerBlock.Bytes(),
		EndStream:     req.Body == nil || req.Body == http.NoBody,
		EndHeaders:    true,
		Priority:      fp.PriorityParam,
	})
	writeMu.Unlock()

	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("write headers: %w", err)
	}

	// Handle Body upload
	if req.Body != nil && req.Body != http.NoBody {
		buf := make([]byte, 16384)
		for {
			n, err := req.Body.Read(buf)
			if n > 0 {
				writeMu.Lock()
				framer.WriteData(streamID, false, buf[:n])
				writeMu.Unlock()
			}
			if err != nil {
				writeMu.Lock()
				framer.WriteData(streamID, true, nil)
				writeMu.Unlock()
				break
			}
		}
	}

	select {
	case res := <-respChan:
		return res, nil
	case err := <-errChan:
		return nil, err
	case <-readLoopDone:
		return nil, errors.New("connection closed before response headers received")
	case <-time.After(30 * time.Second):
		conn.Close()
		return nil, errors.New("timeout waiting for response headers")
	}
}

// Helper to decode HPACK
func decodeHPACK(frag []byte) ([]hpack.HeaderField, error) {
	var headers []hpack.HeaderField
	decoder := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		headers = append(headers, f)
	})
	if _, err := decoder.Write(frag); err != nil {
		return nil, err
	}
	return headers, nil
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
		Timeout:   60 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 10 * time.Second,
				}
				return d.DialContext(ctx, "udp", "1.1.1.1:53")
			},
		},
	}

	// Select your desired fingerprint here (Firefox or Chrome)
	p.requestTransport = &UTLSTransport{
		Fingerprint:   utls.HelloCustom, // Or HelloChrome_120
		H2Fingerprint: Firefox135H2Fingerprint, // Swap with Chrome131H2Fingerprint
		Dialer:        p.netDialer,
		DialTimeout:   15 * time.Second,
	}

	p.requestClient = &http.Client{
		Timeout:   60 * time.Second,
		Transport: p.requestTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return p, nil
}

// Start starts the proxy on the given address.
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
		p.proxyWebsocket(w, r)
		return
	}
	//log.Printf("[uTLS ProxyHTTP r] %s", r)

	r.RequestURI = ""
	removeRequestHopHeaders(r.Header)

	resp, err := p.requestClient.Do(r)
	if err != nil {
		log.Printf("error making request: %v", redacted.Redacted(err))
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeResponseHopHeaders(resp.Header)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyConnect proxies the initial CONNECT and subsequent data.
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

	for {
		req, err := http.ReadRequest(connReader)
		if err != nil {
			if err != io.EOF {
				msg := err.Error()
				if strings.Contains(msg, "tls: ") {
					log.Printf("adding %s to ignored hosts", redacted.Redacted(host))
					p.addTransparentHost(host)
				}
				if !strings.HasSuffix(msg, "connection reset by peer") && !strings.HasSuffix(msg, "An existing connection was forcibly closed by the remote host.") {
					log.Printf("reading request(%s): %v", redacted.Redacted(connReq.Host), err)
				}
			}
			break
		}
		req.URL.Host = connReq.Host

		if isWS(req) {
			p.proxyWebsocketTLS(req, tlsConfig, tlsConn)
			break
		}

		removeRequestHopHeaders(req.Header)
		req.URL.Scheme = "https"

		filterResp, err := p.filter.HandleRequest(req)
		if err != nil {
			log.Printf("handling request for %q: %v", redacted.Redacted(req.URL), err)
		}
		if filterResp != nil {
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
			filterResp.Write(tlsConn)
			if req.Close {
				break
			}
			continue
		}

		req.RequestURI = ""
		req.URL.Host = host
		log.Printf("[uTLS ProxyConnect req] %s", req)

		resp, err := p.requestClient.Do(req)
		if err != nil {
			if strings.Contains(err.Error(), "tls: ") {
				log.Printf("adding %s to ignored hosts", redacted.Redacted(host))
				p.addTransparentHost(host)
			}
			log.Printf("roundtrip(%s): %v", redacted.Redacted(connReq.Host), err)
			response := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\n\r\n%s", err.Error())
			tlsConn.Write([]byte(response))
			break
		}

		if resp.Header.Get("Content-Length") == "" && resp.ContentLength >= 0 {
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
		}
		if resp.ContentLength == -1 {
			resp.TransferEncoding = []string{"chunked"}
		}

		removeResponseHopHeaders(resp.Header)
		//log.Printf("[uTLS ProxyConnect] %s", resp)

		if err := p.filter.HandleResponse(req, resp); err != nil {
			log.Printf("error handling response by filter for %q: %v", redacted.Redacted(req.URL), err)
			resp.Body.Close()
			response := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\n\r\n%s", err.Error())
			tlsConn.Write([]byte(response))
			break
		}

		if err := resp.Write(tlsConn); err != nil {
			log.Printf("writing response(%q): %v", redacted.Redacted(connReq.Host), err)
			resp.Body.Close()
			break
		}

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

func (p *Proxy) addTransparentHost(host string) {
	p.transparentHostsMu.Lock()
	defer p.transparentHostsMu.Unlock()
	p.transparentHosts = append(p.transparentHosts, host)
}

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

func tunnelConn(dst io.Writer, src io.Reader, done chan<- struct{}) {
	if _, err := io.Copy(dst, src); err != nil && !isCloseable(err) {
		log.Printf("copying: %v", err)
	}
	done <- struct{}{}
}

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

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeResponseHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func removeRequestHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		if h == "Te" {
			// RFC 7540 Section 8.1.2.2: The TE header field MAY be present in an HTTP/2 request;
			// when it is, it MUST NOT contain any value other than "trailers".
			// Firefox sends "te: trailers".
			if te := header.Get("Te"); te != "" {
				// Canonicalize to "trailers" or remove if it contains other unsupported values for H2.
				if strings.Contains(strings.ToLower(te), "trailers") {
					header.Set("Te", "trailers")
					continue // Keep it
				}
			}
		}
		header.Del(h)
	}
}
