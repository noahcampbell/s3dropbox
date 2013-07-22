package transport

import (
	"net/url"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const (
	UPLOAD_POLICY_EXAMPLE = `{ "expiration": "2007-12-01T12:00:00.000Z",
  "conditions": [
    {"bucket": "johnsmith"},
    ["starts-with", "$key", "user/eric/"],
    {"acl": "public-read"},
    {"success_action_redirect": "http://johnsmith.s3.amazonaws.com/successful_upload.html"},
    ["starts-with", "$Content-Type", "image/"],
    {"x-amz-meta-uuid": "14365123651274"},
    ["starts-with", "$x-amz-meta-tag", ""]
  ]
}
`
)

func TestDegenerateInvalidPolicy(t *testing.T) {
	policyReader := strings.NewReader("{}")
	if _, ok := NewSingleFileUploader(policyReader, "test.ext", nil); ok == nil {
		t.Fatalf("Expected NewSingleFileUploader to not return a correctly allocated reference.")
	}
}

func checkHTTPMethodIsPost(t *testing.T, uploader Uploader) {
	if uploader.httpRequest().Method != "POST" {
		t.Fatalf("Request should be POST")
	}
}

func checkHTTPURLEquals(t *testing.T, uploader Uploader, urlString string) {
	url, ok := url.Parse(urlString)
	if ok != nil {
		t.Fatalf("Unable to parse url.")
	}
	if !reflect.DeepEqual(uploader.httpRequest().URL, url) {
		t.Fatalf("Request URL is not correct.  Expect:\n%+v\nActual:\n%+v", url, uploader.httpRequest().URL)
	}
}

func checkHTTPEnclosureType(t *testing.T, request *http.Request) {
	contentTypeHeader := request.Header["Content-Type"]
	if len(contentTypeHeader) == 0 {
		t.Fatalf("Content-Type not specified")
	}
	if contentTypeHeader[0] != "multipart/form-data" {
		t.Fatalf("Expected content type to be multipart/form-data")
	}
}

type clientWatcher struct {
	t *testing.T
}

func (c *clientWatcher) RoundTrip(req *http.Request) (res *http.Response, e error) {
	checkHTTPEnclosureType(c.t, req)
	return 
}

func TestUploadFileConstructor(t *testing.T) {
	policyReader := strings.NewReader(UPLOAD_POLICY_EXAMPLE)
	fileToUpload := "file1.ext"
	fileReader := strings.NewReader("file contents")
	uploader, ok := NewSingleFileUploader(policyReader, fileToUpload, fileReader)
	if ok != nil {
		t.Fatalf("Unable to create a SingleFileUploader")
	}
	client := http.Client{Transport: &clientWatcher{t: t}}
	client.Do(uploader.httpRequest())
	checkHTTPMethodIsPost(t, uploader)
	checkHTTPURLEquals(t, uploader, "https://johnsmith.s3.amazonaws.com/user/eric/file1.ext")
}
