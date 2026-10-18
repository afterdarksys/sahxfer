//go:build !unix

package cli

import (
	"os"

	"github.com/afterdarksys/sahxfer/internal/code"
)

// inheritedFD is unix only. The agent does not run recv elsewhere.
func inheritedFD(int, string) (*os.File, error) {
	return nil, code.New("agent_unsupported")
}
