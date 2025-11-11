package gitsync

import (
	"log"
	"net/http"
	"net/http/httputil"
	"os"
)

// LoggingTransport is an http.RoundTripper that logs requests and responses.
type LoggingTransport struct {
	Transport http.RoundTripper
	Logger    *log.Logger
}

// NewLoggingTransport creates a new LoggingTransport.  If transport is nil,
// http.DefaultTransport is used.  If logger is nil, a default logger to
// stderr is used.
func NewLoggingTransport(transport http.RoundTripper, logger *log.Logger) *LoggingTransport {
	if transport == nil {
		transport = http.DefaultTransport
	}
	if logger == nil {
		logger = log.New(os.Stderr, "http-log: ", log.LstdFlags)
	}
	return &LoggingTransport{
		Transport: transport,
		Logger:    logger,
	}
}

// RoundTrip executes a single HTTP transaction, logging the request and response.
func (t *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Dump the request
	reqDump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		t.Logger.Printf("Error dumping request: %v", err)
	} else {
		t.Logger.Printf("Request:\n%s", string(reqDump))
	}

	// Make the request
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		t.Logger.Printf("Error making request: %v", err)
		return resp, err // Return the response and error, even if the response is nil.
	}

	// Dump the response
	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		t.Logger.Printf("Error dumping response: %v", err)
	} else {
		t.Logger.Printf("Response:\n%s", string(respDump))
	}

	return resp, nil
}
