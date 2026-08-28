// A marker writer built as a static Go binary.
//
// The Go toolchain links this program statically when CGO is off. A static
// Go binary is the normal shape of gh, kubectl, helm, terraform, docker and
// most other tools that a coding agent runs. The dynamic linker never runs
// for such a program, so LD_PRELOAD can inject nothing into it.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gomarker MARKER_PATH")
		os.Exit(2)
	}
	if err := os.WriteFile(os.Args[1], []byte("marker written by a static Go binary\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
