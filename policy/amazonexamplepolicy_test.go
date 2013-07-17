package policy

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

const (
	// n.b. remove the .000 nano marker for original

	aws_example_file_upload_policy = `{ "expiration": "2007-12-01T12:00:00.000Z",
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
	aws_example_text_area_upload = `{ "expiration": "2007-12-01T12:00:00.000Z",
  "conditions": [
    {"bucket": "johnsmith"},
    ["starts-with", "$key", "user/eric/"],
    {"acl": "public-read"},
    {"success_action_redirect": "http://johnsmith.s3.amazonaws.com/new_post.html"},
    ["eq", "$Content-Type", "text/html"],
    {"x-amz-meta-uuid": "14365123651274"},
    ["starts-with", "$x-amz-meta-tag", ""]
  ]
}
`
)

func toObject(t *testing.T, bytes []byte) (obj *Policy) {
	ok := json.Unmarshal(bytes, &obj)
	if ok != nil {
		t.Errorf("Unable to unmarshal example 1 policy: %s", ok)
	}
	return
}

func TestAWSFileUploadExample(t *testing.T) {
	policy, _ := NewPolicy(time.Date(2007, time.December, 1, 12, 0, 0, 0, time.UTC))
	policy.AddConditionEq("bucket", "johnsmith")
	policy.AddConditionStartsWith("$key", "user/eric/")
	policy.AddConditionEq("acl", "public-read")
	policy.AddConditionEq("success_action_redirect", "http://johnsmith.s3.amazonaws.com/successful_upload.html")
	policy.AddConditionStartsWith("$Content-Type", "image/")
	policy.AddConditionEq("x-amz-meta-uuid", "14365123651274")
	policy.AddConditionStartsWith("$x-amz-meta-tag", "")
	raw, _ := json.Marshal(policy)
	checkSemanticallyEqual(t, []byte(aws_example_file_upload_policy), raw)
}

func TestAWSTextAreaUploadExample(t *testing.T) {
	policy, _ := NewPolicy(time.Date(2007, time.December, 1, 12, 0, 0, 0, time.UTC))
	policy.AddConditionEq("bucket", "johnsmith")
	policy.AddConditionStartsWith("$key", "user/eric/")
	policy.AddConditionEq("acl", "public-read")
	policy.AddConditionEq("success_action_redirect", "http://johnsmith.s3.amazonaws.com/new_post.html")
	policy.AddConditionEq("$Content-Type", "text/html")
	policy.AddConditionEq("x-amz-meta-uuid", "14365123651274")
	policy.AddConditionStartsWith("$x-amz-meta-tag", "")
	raw, _ := json.Marshal(policy)
	checkSemanticallyEqual(t, []byte(aws_example_text_area_upload), raw)
}

func checkSemanticallyEqual(t *testing.T, raw1, raw2 []byte) {
	obj1 := toObject(t, raw1)
	obj2 := toObject(t, raw2)

	if !reflect.DeepEqual(obj1, obj2) {
		t.Errorf("JSON policy docs are not semantically equivalent.\nexample: %+v\n policy: %+v", obj1, obj2)
	}
}

type AWSSuite struct {
	t *testing.T
	p *Policy
}

func (s *AWSSuite) checkConditionMatches(key, value string) {
	if !s.p.ConditionMatches(key, value) {
		s.t.Errorf("%s did not match value: %s", key, value)
	}
}

func (s *AWSSuite) checkUploadOccursBefore(time time.Time) {
	if s.p.Expiration != time {
		s.t.Errorf("Expiration %s is not equal to %s", s.p.Expiration, time)
	}
}

func (suite *AWSSuite) checkContentUploadedToBucket(value string) {
	suite.checkConditionMatches("bucket", value)
}

func (suite *AWSSuite) checkKeyStartsWith(value string) {
	suite.checkConditionMatches("$key", value)
}

func (s *AWSSuite) checkACL(value string) {
	s.checkConditionMatches("acl", value)
}

func (suite *AWSSuite) checkSuccessActionRedirect(value string) {
	suite.checkConditionMatches("success_action_redirect", value)
}

func (suite *AWSSuite) checkContentType(value string) {
	suite.checkConditionMatches("$Content-Type", value)
}

func (suite *AWSSuite) checkMetaUUID(value string) {
	suite.checkConditionMatches("x-amz-meta-uuid", value)
}

func (suite *AWSSuite) checkMetaTag(value string) {
	suite.checkConditionMatches("$x-amz-meta-tag", value)
}

func TestAWSFileUploadExampleParse(t *testing.T) {
	policy, ok := ParsePolicy([]byte(aws_example_file_upload_policy))
	if ok != nil {
		t.Errorf("Unable to parse AWS File Upload Example policy. %s", ok)
	}
	suite := AWSSuite{t, policy}
	suite.checkUploadOccursBefore(time.Date(2007, time.December, 1, 12, 0, 0, 0, time.UTC))
	suite.checkContentUploadedToBucket("johnsmith")
	suite.checkKeyStartsWith("user/eric/")
	suite.checkACL("public-read")
	suite.checkSuccessActionRedirect("http://johnsmith.s3.amazonaws.com/successful_upload.html")
	suite.checkContentType("image/")
	suite.checkMetaUUID("14365123651274")
	suite.checkMetaTag("")
}

func TestAWSTextUploadExampleParse(t *testing.T) {
	policy, ok := ParsePolicy([]byte(aws_example_text_area_upload))
	if ok != nil {
		t.Errorf("Unable to parse AWS Text Area Upload example policy. %s", ok)
	}

	suite := AWSSuite{t, policy}
	suite.checkUploadOccursBefore(time.Date(2007, time.December, 1, 12, 0, 0, 0, time.UTC))
	suite.checkContentUploadedToBucket("johnsmith")
	suite.checkKeyStartsWith("user/eric/")
	suite.checkACL("public-read")
	suite.checkSuccessActionRedirect("http://johnsmith.s3.amazonaws.com/new_post.html")
	suite.checkContentType("text/html")
	suite.checkMetaUUID("14365123651274")
	suite.checkMetaTag("")
}
