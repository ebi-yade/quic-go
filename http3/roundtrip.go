package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"

	"github.com/ebi-yade/altsvc-go"
	quic "github.com/lucas-clemente/quic-go"

	"golang.org/x/net/http/httpguts"
)

type roundTripCloser interface {
	http.RoundTripper
	io.Closer
}

// RoundTripper implements the http.RoundTripper interface
type RoundTripper struct {
	mutex sync.Mutex

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// QuicConfig is the quic.Config used for dialing new connections.
	// If nil, reasonable default values will be used.
	QuicConfig *quic.Config

	// Enable support for HTTP/3 datagrams.
	// If set to true, QuicConfig.EnableDatagram will be set.
	// See https://www.ietf.org/archive/id/draft-schinazi-masque-h3-datagram-02.html.
	EnableDatagrams bool

	// Dial specifies an optional dial function for creating QUIC
	// connections for requests.
	// If Dial is nil, quic.DialAddrEarly will be used.
	Dial func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error)

	// MaxResponseHeaderBytes specifies a limit on how many response bytes are
	// allowed in the server's response header.
	// Zero means to use a default limit.
	MaxResponseHeaderBytes int64

	// See https://www.ietf.org/archive/id/draft-ietf-quic-http-34.html#section-3.1.
	ConnectionDiscovery
	// for ConnectionDiscovery: Alt-Svc
	altSvcs map[string][]altSvc

	clients map[string]roundTripCloser
}

// RoundTripOpt are options for the Transport.RoundTripOpt method.
type RoundTripOpt struct {
	// OnlyCachedConn controls whether the RoundTripper may create a new QUIC connection.
	// If set true and no cached connection is available, RoundTrip will return ErrNoCachedConn.
	OnlyCachedConn bool
	// SkipSchemeCheck controls whether we check if the scheme is https.
	// This allows the use of different schemes, e.g. masque://target.example.com:443/.
	SkipSchemeCheck bool
}

type subTrip struct {
	res *http.Response
	err error
}

type ConnectionDiscovery int

const (
	ConnectionDiscoveryAltSvc ConnectionDiscovery = iota
	ConnectionDiscoveryHappyEyeballs
)

type altSvc struct {
	altsvc.Service
	expiredAt time.Time
}

var _ roundTripCloser = &RoundTripper{}

// ErrNoCachedConn is returned when RoundTripper.OnlyCachedConn is set
var ErrNoCachedConn = errors.New("http3: no cached connection was available")

// RoundTripOpt is like RoundTrip, but takes options.
func (r *RoundTripper) RoundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	if req.URL == nil {
		closeRequestBody(req)
		return nil, errors.New("http3: nil Request.URL")
	}
	if req.URL.Host == "" {
		closeRequestBody(req)
		return nil, errors.New("http3: no Host in request URL")
	}
	if req.Header == nil {
		closeRequestBody(req)
		return nil, errors.New("http3: nil Request.Header")
	}

	if req.URL.Scheme == "https" {
		for k, vv := range req.Header {
			if !httpguts.ValidHeaderFieldName(k) {
				return nil, fmt.Errorf("http3: invalid http header field name %q", k)
			}
			for _, v := range vv {
				if !httpguts.ValidHeaderFieldValue(v) {
					return nil, fmt.Errorf("http3: invalid http header field value %q for key %v", v, k)
				}
			}
		}
	} else if !opt.SkipSchemeCheck {
		closeRequestBody(req)
		return nil, fmt.Errorf("http3: unsupported protocol scheme: %s", req.URL.Scheme)
	}

	if req.Method != "" && !validMethod(req.Method) {
		closeRequestBody(req)
		return nil, fmt.Errorf("http3: invalid method %q", req.Method)
	}

	hostname := authorityAddr("https", hostnameFromRequest(req))
	cl, err := r.getClient(hostname, opt.OnlyCachedConn)
	if err != nil {
		return nil, err
	}

	tcp := http.DefaultTransport.(*http.Transport).Clone()
	tcp.TLSClientConfig = &tls.Config{InsecureSkipVerify: r.TLSClientConfig.InsecureSkipVerify}
	tcpClient := &http.Client{Transport: tcp}

	switch r.ConnectionDiscovery {
	case ConnectionDiscoveryAltSvc:
		ownedSvcs, ok := r.getAltServices(hostname)
		h3Ready := false
		for _, s := range ownedSvcs {
			if strings.HasPrefix(s.ProtocolID, "h3") {
				h3Ready = true
				break
			}
		}
		if ok && h3Ready {
			res, err := cl.RoundTrip(req)
			return res, err
		}
		res, err := tcpClient.Do(req)
		hdr := res.Header.Get("Alt-Svc")
		svcs, err := altsvc.Parse(hdr)
		r.setAltServices(hostname, svcs)
		return res, err
	case ConnectionDiscoveryHappyEyeballs:
		// ctxQuic, cancelQuic := context.WithCancel(req.Context())
		ctxQuic := req.Context()
		quicClient, ok := cl.(*client)
		if !ok { // TODO: return error
			panic("client is not http3.client")
		}
		ctxTmp, cancelSelf := context.WithCancel(req.Context())
		trace := &httptrace.ClientTrace{
			TLSHandshakeDone: func(state tls.ConnectionState, err error) {
				if quicClient.session != nil {
					select {
					case <-quicClient.session.HandshakeComplete().Done():
						cancelSelf()
					default:
					}
				}
			},
		}
		ctxTcp := httptrace.WithClientTrace(ctxTmp, trace)

		var once sync.Once
		resChan := make(chan subTrip)
		go func() { // QUIC Subroutine
			req = req.Clone(ctxQuic)
			res, err := cl.RoundTrip(req)
			if res != nil {
				once.Do(func() { resChan <- subTrip{res: res, err: err} })
			}
		}()
		go func() { // TCP Subroutine
			req = req.Clone(ctxTcp)
			res, err := tcpClient.Do(req)
			if res != nil {
				once.Do(func() { resChan <- subTrip{res: res, err: err} })
			}
		}()
		sub := <-resChan
		return sub.res, sub.err
	default:
		return nil, fmt.Errorf("invalid value: ConnectionDiscovery")
	}
}

// RoundTrip does a round trip.
func (r *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.RoundTripOpt(req, RoundTripOpt{})
}

func (r *RoundTripper) getClient(hostname string, onlyCached bool) (http.RoundTripper, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.clients == nil {
		r.clients = make(map[string]roundTripCloser)
	}

	client, ok := r.clients[hostname]
	if !ok {
		if onlyCached {
			return nil, ErrNoCachedConn
		}
		var err error
		client, err = newClient(
			hostname,
			r.TLSClientConfig,
			&roundTripperOpts{
				EnableDatagram:     r.EnableDatagrams,
				DisableCompression: r.DisableCompression,
				MaxHeaderBytes:     r.MaxResponseHeaderBytes,
			},
			r.QuicConfig,
			r.Dial,
		)
		if err != nil {
			return nil, err
		}
		r.clients[hostname] = client
	}
	return client, nil
}

func (r *RoundTripper) setAltServices(hostname string, svcs []altsvc.Service) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	val := make([]altSvc, len(svcs))
	for _, s := range svcs {
		if s.Clear == true {
			delete(r.altSvcs, hostname)
			return
		}
		v := altSvc{Service: s}
		if v.Persist != 1 {
			v.expiredAt = time.Now().Add(time.Duration(s.MaxAge) * time.Second)
		}
		val = append(val, v)
	}
	if r.altSvcs == nil {
		r.altSvcs = map[string][]altSvc{hostname: val}
	}
	r.altSvcs[hostname] = val
}

// getAltServices returns the slice of valid altSvc.
func (r *RoundTripper) getAltServices(hostname string) ([]altSvc, bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	svcs, ok := r.altSvcs[hostname]
	ret := make([]altSvc, len(svcs))
	for _, s := range svcs {
		if !time.Now().After(s.expiredAt) || s.Persist == 1 {
			ret = append(ret, s)
		}
	}
	return ret, ok
}

// Close closes the QUIC connections that this RoundTripper has used
func (r *RoundTripper) Close() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, client := range r.clients {
		if err := client.Close(); err != nil {
			return err
		}
	}
	r.clients = nil
	return nil
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

func validMethod(method string) bool {
	/*
				     Method         = "OPTIONS"                ; Section 9.2
		   		                    | "GET"                    ; Section 9.3
		   		                    | "HEAD"                   ; Section 9.4
		   		                    | "POST"                   ; Section 9.5
		   		                    | "PUT"                    ; Section 9.6
		   		                    | "DELETE"                 ; Section 9.7
		   		                    | "TRACE"                  ; Section 9.8
		   		                    | "CONNECT"                ; Section 9.9
		   		                    | extension-method
		   		   extension-method = token
		   		     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

// copied from net/http/http.go
func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}
