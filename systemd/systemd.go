package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/mrunalp/hooks"
)

const (
	journalDir = "/var/log/journal"
)

func setupRun(state *hooks.State) error {
	runDir := filepath.Join(state.Root, "/run")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return err
	}
	flags := syscall.MS_NOEXEC | syscall.MS_NODEV | syscall.MS_NOSUID
	if err := syscall.Mount("tmpfs", runDir, "tmpfs", uintptr(flags), "mode=755"); err != nil {
		return err
	}
	return nil
}
func setupJournal(state *hooks.State) error {
	jDir := filepath.Join(journalDir, state.ID)
	if err := os.MkdirAll(jDir, 0666); err != nil {
		return err
	}

	jcDir := filepath.Join(state.Root, journalDir)
	if err := os.MkdirAll(jcDir, 0666); err != nil {
		return err
	}

	flags := syscall.MS_BIND | syscall.MS_REC
	if err := syscall.Mount(jDir, jcDir, "bind", uintptr(flags), ""); err != nil {
		return err
	}
	return nil
}

func setupMachineID(state *hooks.State) error {
	etcDir := filepath.Join("/tmp", state.Root, "/etc")
	if err := os.MkdirAll(etcDir, 0666); err != nil {
		return err
	}
	mFile := filepath.Join(etcDir, "machine-id")
	if err := ioutil.WriteFile(mFile, []byte(state.ID), 0666); err != nil {
		return err
	}
	cmFile := filepath.Join(state.Root, "/etc/machine-id")
	f, err := os.Create(cmFile)
	if err != nil {
		return err
	}
	defer f.Close()
	flags := syscall.MS_BIND | syscall.MS_REC
	if syscall.Mount(mFile, cmFile, "bind", uintptr(flags), ""); err != nil {
		return err
	}
	return nil
}

func setup(state *hooks.State) error {
	if err := setupRun(state); err != nil {
		return err
	}
	if err := setupJournal(state); err != nil {
		return err
	}
	if err := setupMachineID(state); err != nil {
		return err
	}
	return nil
}

func teardownJournal(state *hooks.State) error {
	jcDir := filepath.Join(state.Root, journalDir)
	if err := syscall.Unmount(jcDir, syscall.MNT_DETACH); err != nil {
		return err
	}
	return nil
}

func teardownMachineID(state *hooks.State) error {
	cmFile := filepath.Join(state.Root, "/etc/machine-id")
	if err := syscall.Unmount(cmFile, syscall.MNT_DETACH); err != nil {
		return err
	}

	etcDir := filepath.Join("/tmp", state.Root, "/etc")
	mFile := filepath.Join(etcDir, "machine-id")
	if err := os.Remove(mFile); err != nil {
		return err
	}
	if err := os.RemoveAll(etcDir); err != nil {
		return err
	}
	return nil
}

func teardown(state *hooks.State) error {
	var err, err2 error
	if err = teardownJournal(state); err != nil {
		log.Printf("Journal teardown error: %q", err)
	}
	if err2 := teardownMachineID(state); err2 != nil {
		log.Printf("Machine ID teardown error: %q", err)
	}
	if err != nil || err2 != nil {
		return fmt.Errorf("Journal teardown error: %q, Machine ID teardown error: %q", err, err2)
	}
	return nil
}

func main() {
	state, err := hooks.GetStateFromStdin()
	if err != nil {
		log.Fatal(err)
	}

	switch os.Args[0] {
	case "prestart":
		err = setup(state)
	case "poststop":
		err = teardown(state)
	default:
		log.Fatalf("Invalid argument: %q", os.Args[0])
	}
	if err != nil {
		log.Fatal(err)
	}
}
