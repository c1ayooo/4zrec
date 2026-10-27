package cloud

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// This file is the seam the brief calls out: every vendor SDK must send through
// the injected core.HTTPDoer so the host's scope check, rate limit and audit
// cannot be bypassed by a kit-owned client.
//
// Each SDK wants a slightly different shape, and all four are covered by the
// one adapter below:
//
//	aws-sdk-go-v2          config.WithHTTPClient(httpClient)      -> Do
//	alibabacloud-go         openapi.Config.HttpClient             -> Call
//	tencentcloud-sdk-go     client.WithHttpTransport(rt)          -> RoundTrip
//	huaweicloud-sdk-go-v3   httpConfig.WithHttpRoundTripper(rt)   -> RoundTrip
//	oss / cos               oss.Config.WithHttpClient / NewClient -> RoundTrip
//
// maxRequestBody bounds how much of a request body is buffered before handing it
// to the port: the port takes bytes, and every cloud request here is small.
const maxRequestBody = 1 << 20

// httpDoerClient adapts a core.HTTPDoer to net/http's RoundTripper and to the
// darabonba HttpClient interface.
type httpDoerClient struct {
	doer core.HTTPDoer
	// timeout applies when the request carries no deadline of its own.
	timeout time.Duration
}

// newHTTPDoerClient wraps a doer. A nil doer is not an error here: the kit
// reports "unavailable" when a tool actually needs it, so a host that never
// calls a cloud tool does not have to wire one.
func newHTTPDoerClient(doer core.HTTPDoer, timeout time.Duration) *httpDoerClient {
	return &httpDoerClient{doer: doer, timeout: timeout}
}

// client returns the *http.Client to hand to an SDK: its transport is this
// adapter, so the SDK's every request reaches the port.
func (c *httpDoerClient) client() *http.Client { return &http.Client{Transport: c} }

// RoundTrip implements http.RoundTripper: it converts the SDK's request into a
// core.Request, calls the port, and rebuilds an *http.Response body for the
// SDK to parse.
func (c *httpDoerClient) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.doer == nil {
		return nil, core.Unavailable("cloudkit: HTTPDoer 未注入，无法发起云 API 调用")
	}
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBody))
		if err != nil {
			return nil, core.InvalidInput("cloudkit: 读取请求体失败: " + err.Error())
		}
		_ = req.Body.Close()
		body = b
	}
	headers := make(map[string]string, len(req.Header)+1)
	for k, vs := range req.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	if req.Host != "" {
		headers["Host"] = req.Host
	}
	res, err := c.doer.Do(req.Context(), core.Request{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: headers,
		Body:    body,
		Timeout: c.timeout,
	})
	if err != nil {
		// Returned verbatim: a scope denial from the host must surface as
		// blocked, not be re-classified as a vendor failure.
		return nil, err
	}
	return responseFor(req, res), nil
}

// Call implements the darabonba HttpClient interface (alibabacloud-go). The
// transport argument is deliberately unused: the injected doer owns transport
// policy, so the SDK cannot supply its own.
func (c *httpDoerClient) Call(req *http.Request, _ *http.Transport) (*http.Response, error) {
	return c.RoundTrip(req)
}

// responseFor rebuilds the SDK's view of the response from the port's bytes.
func responseFor(req *http.Request, res *core.Response) *http.Response {
	status := res.Status
	if status == 0 {
		status = http.StatusBadGateway
	}
	header := http.Header{}
	for k, vs := range res.Headers {
		for _, v := range vs {
			header.Add(k, v)
		}
	}
	return &http.Response{
		Status:        http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(res.Body)),
		ContentLength: int64(len(res.Body)),
		Request:       req,
	}
}
