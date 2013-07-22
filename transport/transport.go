package transport

import (
	"bytes"
	"fmt"
	"github.com/noahcampbell/s3dropbox/policy"
	"io"
	"net/http"
	"net/url"
	"mime/multipart"
)

type Uploader interface {
	Upload()
	httpRequest() (req *http.Request)
}

type httpUploader struct {
	request *http.Request
}

type Options struct {
	bucket string
	key    string
}

func (h httpUploader) Upload() {
}

func (h httpUploader) httpRequest() (req *http.Request) {
	return h.request
}

func (o *Options) getBucketFrom(p *policy.Policy) (found bool) {
	if bucket, found := p.Condition("bucket"); found {
		o.bucket = bucket.ValueString()
	}
	return
}

func (o *Options) getKeyFrom(p *policy.Policy) (found bool) {
	if path, found := p.Condition("$key"); found {
		o.key = path.ValueString()
	}
	return
}

func extractOptionsFromPolicy(policy *policy.Policy) (options *Options) {
	options = &Options{}
	options.getBucketFrom(policy)
	options.getKeyFrom(policy)
	return
}

/*
NewSingleFileUploader creates a request formatted for AWS S3 Form Upload.
Values, like bucketname and base path, are interpreted from the policy file.
*/
func NewSingleFileUploader(policyReader io.Reader, filename string, fileReader io.Reader) (uploader Uploader, ok error) {
	prb := bytes.NewBuffer([]byte(""))
	if _, ok := prb.ReadFrom(policyReader); ok != nil {
		return nil, ok
	}

	var p *policy.Policy
	if p, ok = policy.ParsePolicy(prb.Bytes()); ok != nil {
		return nil, ok
	}
	options := extractOptionsFromPolicy(p)

	uploadURL := &url.URL{Scheme: "https"}
	uploadURL.Host = fmt.Sprintf("%s.s3.amazonaws.com", options.bucket)

	keyURL, ok := url.Parse(options.key)
	if ok != nil {
		return nil, ok
	}

	filenameURL, ok := url.Parse(filename)
	if ok != nil {
		return nil, ok
	}

	uploadURL = uploadURL.ResolveReference(keyURL)
	uploadURL = uploadURL.ResolveReference(filenameURL)
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	foobarWriter, _ := writer.CreateFormField("foobar")
	foobarWriter.Write([]byte("This is a test"))
	if ok = writer.Close(); ok != nil {
		return
	}
	fmt.Printf("%s", body)
	request, ok := http.NewRequest("POST", uploadURL.String(), body)
	uploader = &httpUploader{request: request}
	return
}
