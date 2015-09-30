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

const (
	journalDir = "/var/log/journal"
)

func setup(state *State) error {
	jDir := filepath.Join(journalDir, state.ID)
	if err := os.MkdirAll(jDir, 0666); err != nil {
		return err
	}

	jcDir := filepath.Join(state.Root, journalDir, state.ID)
	if err := os.MkdirAll(jcDir, 0666); err != nil {
		return err
	}

	flags := syscall.MS_BIND | syscall.MS_REC
	if err := syscall.Mount(jDir, jcDir, "bind", uintptr(flags), ""); err != nil {
		return err
	}
	return nil
}

func teardown(state *State) error {
	jcDir := filepath.Join(state.Root, journalDir, state.ID)
	if err := syscall.Unmount(jcDir, syscall.MNT_DETACH); err != nil {
		return err
	}
	if err := os.RemoveAll(jcDir); err != nil {
		return err
	}

	jDir := filepath.Join(journalDir, state.ID)
	if err := os.RemoveAll(jDir); err != nil {
		return err
	}
	return nil
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

	var err error
	switch os.Args[0] {
	case "prestart":
		err = setup(&state)
	case "poststop":
		err = teardown(&state)
	default:
		log.Fatalf("Invalid argument: %q", os.Args[0])
	}
	if err != nil {
		log.Fatal(err)
	}
}
