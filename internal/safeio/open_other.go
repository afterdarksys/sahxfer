//go:build !darwin && !linux

package safeio

import (
	"os"

	"github.com/afterdarksys/sahxfer/internal/code"
)

// Kernels other than Linux and the Darwin dev walk are agent_unsupported.
// There is no fallback opener.

func openRoot(string) (int, error) { return -1, code.New("agent_unsupported") }

func closefd(int) error { return code.New("agent_unsupported") }

func openReg(int, string) (int, error) { return -1, code.New("agent_unsupported") }

func openDir(int, string) (int, error) { return -1, code.New("agent_unsupported") }

func dupfd(int) (int, error) { return -1, code.New("agent_unsupported") }

func statName(int, string) (int, error) { return 0, code.New("agent_unsupported") }

func createExcl(int, string) (int, error) { return -1, code.New("agent_unsupported") }

func fsyncfd(int) error { return code.New("agent_unsupported") }

func lockfd(int) error { return code.New("agent_unsupported") }

func renameExclusive(int, string, string, bool) error { return code.New("agent_unsupported") }

func unlinkAt(int, string) error { return code.New("agent_unsupported") }

func isAbsent(error) bool { return false }

func openRead(string) (*os.File, error) { return nil, code.New("agent_unsupported") }

func createNew(string) (*os.File, error) { return nil, code.New("agent_unsupported") }
