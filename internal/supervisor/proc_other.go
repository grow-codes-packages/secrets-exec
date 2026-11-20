//go:build !linux

package supervisor

import "os"

// setSubreaper is Linux only; elsewhere orphans go to init as usual.
func setSubreaper() error { return nil }

// isTerminal is conservative off Linux: no own process group for the child.
func isTerminal(*os.File) bool { return true }
