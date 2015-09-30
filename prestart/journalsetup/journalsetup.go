package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"syscall"
)

type State struct {
	Version string `json:"version"`
	ID      string `json:"id"`
	Pid     int    `json:"pid"`
	Root    string `json:"root"`
}

func main() {
	var state State
	if err := json.NewDecoder(os.Stdin).Decode(&state); err != nil {
		log.Fatal(err)
	}

	if state.ID == "" {
		log.Fatalf("ID should not be empty")
	}

	if state.Root == "" {
		log.Fatalf("Root should not be empty")
	}

	jDir := filepath.Join("/var/log/journal", state.ID)
	if err := os.MkdirAll(jDir, 0666); err != nil {
		log.Fatal(err)
	}

	jcDir := filepath.Join(state.Root, "/var/log/journal", state.ID)
	if err := os.MkdirAll(jcDir, 0666); err != nil {
		log.Fatal(err)
	}

	flags := syscall.MS_BIND | syscall.MS_REC
	if err := syscall.Mount(jDir, jcDir, "bind", uintptr(flags), ""); err != nil {
		log.Fatal(err)
	}
}
