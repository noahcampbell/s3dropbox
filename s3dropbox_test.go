package s3dropbox

import (
	"testing"
)

func TestDegenerateCreateS3DropboxClientNoArgs(t *testing.T) {
	ok := NewS3DropboxClient()
	if ok == nil {
		t.Errorf("No Arguments should produce an error.")
	}
}

/*
func TestAddPolicyToSigner(t* testing.T) {
	signer, ok := NewS3DropboxSigner("123", "321")
	now := time.Now()
	conditions := [...]Condition{{acl: "private"}}
	policy := Policy{now, conditions}
	ok := signer.AddPolicy(policy)
	if ok != nil {
		t.Errorf("Unable to add a policy")
	}
}
*/
