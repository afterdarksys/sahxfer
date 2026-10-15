//go:build !unix

package secfile

import (
	"os"

	"github.com/afterdarksys/sahxfer/internal/code"
)

// CurrentUID is unused off unix. Tests on unix replace the unix variable.
var CurrentUID = os.Getuid

// OpenRead is refused. This build has no O_NOFOLLOW check.
func OpenRead(string) (*os.File, os.FileInfo, error) {
	return nil, nil, code.New("agent_unsupported")
}

// CheckDir0700 is refused. This build has no owner check.
func CheckDir0700(string) error {
	return code.New("agent_unsupported")
}

// CreateExcl is refused. This build has no O_NOFOLLOW create.
func CreateExcl(string) (*os.File, error) {
	return nil, code.New("agent_unsupported")
}
