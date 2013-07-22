package transport

import (
	"net/url"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"mime"
	"mime/multipart"
	"io"
	"bytes"
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
	if strings.HasPrefix("multipart/form-data; boundary=", contentTypeHeader[0]) {
		t.Fatalf("Expected content type to start with multipart/form-data; boundary=; got: %s", contentTypeHeader[0])
	}
}

func checkFileAddedToUpload(t *testing.T, request *http.Request, checks []func(t *testing.T, part *multipart.Part)(bool, bool)) {
	contentType := request.Header["Content-Type"][0]
	_, params, _ := mime.ParseMediaType(contentType)
	//fmt.Printf("BODY: %s\n", request.Body)
	reader := multipart.NewReader(request.Body, params["boundary"])
	checksCovered := make([]bool, len(checks))

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if part == nil {
			t.Fatalf("Part is nil")
		}
		
		for i, check := range checks {
			ok, skipped := check(t, part)
			if !skipped {
				if !ok {
					t.Fatalf("Failed check: %v", checks[i])
					return
				}
				checksCovered[i] = true
			}
		}
		if err := part.Close(); err != nil {
			t.Fatalf("Error closing part: %s", err)
		}
	}

	for i, checked := range checksCovered {
		if !checked {
			t.Fatalf("Did not check: %#v", checks[i])
			return
		}
	}
}

func checkPartFileExists(t *testing.T, part *multipart.Part) (ok, skipped bool) {
		if part.FormName() != "file" {
			return false, true
		}

		if part.FileName() != "file1.ext" {
			t.Errorf("Filename not set")
			return
		}	

		return true, false
}

func checkPartSignatureIsValid(t *testing.T, part *multipart.Part) (ok, skipped bool) {
	if part.FormName() != "signature" {
		return false, true
	}

	var pbody bytes.Buffer
	if n, err := pbody.ReadFrom(part); err != nil {
		t.Errorf("Unable to read part: %d %s, %+v", n, err, part)
		return
	}

	if pbody.String() != "ljNZVWWNydBahCG5wWD64fTFEOU=" {
		t.Errorf("Signature: Expected ljNZVWWNydBahCG5wWD64fTFEOU= got: %s", pbody.String())
	}
	ok = true
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
	checkHTTPMethodIsPost(t, uploader)
	checkHTTPURLEquals(t, uploader, "https://johnsmith.s3.amazonaws.com/user/eric/file1.ext")
	checkHTTPEnclosureType(t, uploader.httpRequest())
	checks := []func(t *testing.T, part *multipart.Part) (bool, bool) {
		checkPartFileExists,
		checkPartSignatureIsValid,
	}
	checkFileAddedToUpload(t, uploader.httpRequest(), checks)
}
