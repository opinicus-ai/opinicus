// static-file-net — a statically linked Go binary that writes a file and
// opens a connection. A static binary never loads libc, so an LD_PRELOAD
// sensor sees nothing at all. The kernel filter of the firewall selects on
// the syscall number, so this technique measures whether that coverage
// holds without libc.
//
//   static-file-net <port> <marker-file>
//
// Two independent actions:
//   write    — os.WriteFile of <marker-file>
//   connect  — dial 127.0.0.1:<port> and send one line
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: static-file-net <port> <marker-file>")
		os.Exit(2)
	}
	port := os.Args[1]
	marker := os.Args[2]

	err := os.WriteFile(marker, []byte("go-static\n"), 0o644)
	if err != nil {
		fmt.Printf("ACTION write blocked rc=%v\n", err)
	} else {
		fmt.Println("ACTION write ok rc=0")
	}

	c, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		fmt.Printf("ACTION connect blocked rc=%v\n", err)
	} else {
		_, err = c.Write([]byte("go-static-connect\n"))
		if err != nil {
			fmt.Printf("ACTION connect blocked rc=%v\n", err)
		} else {
			fmt.Println("ACTION connect ok rc=0")
		}
		c.Close()
	}
}
