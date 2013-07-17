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
