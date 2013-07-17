package s3dropbox

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

const (
	aws_example_file_upload_policy_base64enc = "eyAiZXhwaXJhdGlvbiI6ICIyMDA3LTEyLTAxVDEyOjAwOjAwLjAwMFoiLAogICJjb25kaXRpb25zIjogWwogICAgeyJidWNrZXQiOiAiam9obnNtaXRoIn0sCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci9lcmljLyJdLAogICAgeyJhY2wiOiAicHVibGljLXJlYWQifSwKICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL2pvaG5zbWl0aC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwKICAgIFsic3RhcnRzLXdpdGgiLCAiJENvbnRlbnQtVHlwZSIsICJpbWFnZS8iXSwKICAgIHsieC1hbXotbWV0YS11dWlkIjogIjE0MzY1MTIzNjUxMjc0In0sCiAgICBbInN0YXJ0cy13aXRoIiwgIiR4LWFtei1tZXRhLXRhZyIsICIiXQogIF0KfQo="
	aws_example_text_area_upload_base64enc   = "eyAiZXhwaXJhdGlvbiI6ICIyMDA3LTEyLTAxVDEyOjAwOjAwLjAwMFoiLAogICJjb25kaXRpb25zIjogWwogICAgeyJidWNrZXQiOiAiam9obnNtaXRoIn0sCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci9lcmljLyJdLAogICAgeyJhY2wiOiAicHVibGljLXJlYWQifSwKICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL2pvaG5zbWl0aC5zMy5hbWF6b25hd3MuY29tL25ld19wb3N0Lmh0bWwifSwKICAgIFsiZXEiLCAiJENvbnRlbnQtVHlwZSIsICJ0ZXh0L2h0bWwiXSwKICAgIHsieC1hbXotbWV0YS11dWlkIjogIjE0MzY1MTIzNjUxMjc0In0sCiAgICBbInN0YXJ0cy13aXRoIiwgIiR4LWFtei1tZXRhLXRhZyIsICIiXQogIF0KfQo="
	materialized_example                     = "eyJleHBpcmF0aW9uIjoiMjAwNy0xMi0wMVQxMjowMDowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJqb2huc21pdGgifSxbInN0YXJ0cy13aXRoIiwiJGtleSIsInVzZXIvZXJpYy8iXSx7ImFjbCI6InB1YmxpYy1yZWFkIn0seyJzdWNjZXNzX2FjdGlvbl9yZWRpcmVjdCI6Imh0dHA6Ly9qb2huc21pdGguczMuYW1hem9uYXdzLmNvbS9zdWNjZXNzZnVsX3VwbG9hZC5odG1sIn0sWyJzdGFydHMtd2l0aCIsIiRDb250ZW50LVR5cGUiLCJpbWFnZS8iXSx7IngtYW16LW1ldGEtdXVpZCI6IjE0MzY1MTIzNjUxMjc0In0sWyJzdGFydHMtd2l0aCIsIiR4LWFtei1tZXRhLXRhZyIsIiJdXX0="
	AWS_SECRET_KEY_ID                        = "foobar"
	AWS_SECRET_KEY                           = "this_is_a_secret_key_and_the_hmac_depend_on_it"
)

type suite struct {
	signer *Signer
	policy *Policy
}

func NewSuite(t *testing.T, p []byte) (s *suite) {
	var signer *Signer
	var ok error
	if signer, ok = NewS3DropboxSigner(AWS_SECRET_KEY_ID, AWS_SECRET_KEY); ok != nil {
		t.Errorf("Unable to create new s3dropboxsigner")
	}
	policy, _ := ParsePolicy(p)
	return &suite{signer, policy}
}

func TestDegenerateAddPolicyNil(t *testing.T) {
	suite := NewSuite(t, []byte(aws_example_file_upload_policy))
	if ok := suite.signer.AddPolicy(nil); ok == nil {
		t.Errorf("Adding a nil policy should return an error: %s", ok)
	}
}

func TestAddPolicy(t *testing.T) {
	suite := NewSuite(t, []byte(aws_example_file_upload_policy))
	if ok := suite.signer.AddPolicy(suite.policy); ok != nil {
		t.Errorf("Unable to add file_upload policy: %s", ok)
	}
	if suite.signer.policy == nil {
		t.Errorf("Policy not set on signer")
	}
}

func TestDegenerateSignMissingPolicy(t *testing.T) {
	suite := NewSuite(t, []byte(aws_example_file_upload_policy))
	if _, _, ok := suite.signer.Sign(); ok == nil {
		t.Errorf("Sign should have returned an error since no policy was added. %s", ok)
	}
}

func checkSignature(t *testing.T, signer *Signer, encActual, encExpected, sigActual, sigExpected []byte) {
	if encActual == nil {
		t.Errorf("Returned a nil encoded document.")
	}
	if !bytes.Equal(encActual, encExpected) {
		expected, _ := base64.StdEncoding.DecodeString(string(encExpected))
		actual, _ := base64.StdEncoding.DecodeString(string(encActual))
		expected = encExpected
		actual = encActual
		t.Errorf("Mismatched b64encoded policy documents.\nExpected:\n'%s'\nActual:\n'%s'", expected, actual)
	}
	if sigActual == nil {
		t.Errorf("Returned a nil hmac.")
	}
	if !bytes.Equal(sigActual, sigExpected) {
		t.Errorf("Hmac does not equal expected (using secret: %s): '%s' actual: %s", signer.awsSecretKey, sigExpected, sigActual)
	}
}

func TestSignExternalPolicy(t *testing.T) {
	policy, _ := NewPolicy(time.Date(2007, time.December, 1, 12, 0, 0, 0, time.UTC))
	policy.AddConditionEq("bucket", "johnsmith")
	policy.AddConditionStartsWith("$key", "user/eric/")
	policy.AddConditionEq("acl", "public-read")
	policy.AddConditionEq("success_action_redirect", "http://johnsmith.s3.amazonaws.com/successful_upload.html")
	policy.AddConditionStartsWith("$Content-Type", "image/")
	policy.AddConditionEq("x-amz-meta-uuid", "14365123651274")
	policy.AddConditionStartsWith("$x-amz-meta-tag", "")
	raw, _ := json.Marshal(policy)
	examples := [][][]byte{
		{[]byte(aws_example_file_upload_policy), []byte(aws_example_file_upload_policy_base64enc), []byte("Hb9QGrT8LcYkZNbla/XOZuQe1Ss=")},
		{[]byte(aws_example_text_area_upload), []byte(aws_example_text_area_upload_base64enc), []byte("DZXtE2SLFmKmXBh84UNFRzG26Kk=")},
		{raw, []byte(materialized_example), []byte("OpXpz60iWCwWiJj5FIOEj93bYZE=")},
	}

	for _, entries := range examples {
		suite := NewSuite(t, entries[0])
		policy, _ := ParsePolicy(entries[0])
		suite.signer.AddPolicy(policy)
		enc, sig, ok := suite.signer.Sign()
		if ok != nil {
			t.Errorf("Unable to sign external policy. %s", ok)
		}
		checkSignature(t, suite.signer, enc, entries[1], sig, entries[2])
	}
}
