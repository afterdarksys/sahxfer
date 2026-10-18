//go:build !darwin && !linux

package safeio

import (
	"os"

	"github.com/afterdarksys/sahxfer/internal/code"
)

func blockSize(os.FileInfo) int64 { return 4096 }

func extendErr(error) error { return code.New("io") }

// punch is a no-op: the extended range already reads as zero.
func punch(*os.File, int64, int64) {}
