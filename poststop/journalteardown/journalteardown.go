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
	jcDir := filepath.Join(state.Root, "/var/log/journal", state.ID)

	if err := syscall.Unmount(jcDir, syscall.MNT_DETACH); err != nil {
		log.Print(err)
	}

	if err := os.RemoveAll(jcDir); err != nil {
		log.Print(err)
	}

	if err := os.RemoveAll(jDir); err != nil {
		log.Print(err)
	}
}
