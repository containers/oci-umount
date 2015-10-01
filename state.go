package hooks

import (
	"encoding/json"
	"fmt"
	"os"
)

type State struct {
	Version string `json:"version"`
	ID      string `json:"id"`
	Pid     int    `json:"pid"`
	Root    string `json:"root"`
}

func GetStateFromStdin() (*State, error) {
	var state State
	if err := json.NewDecoder(os.Stdin).Decode(&state); err != nil {
		return nil, err
	}

	if state.ID == "" {
		return nil, fmt.Errorf("state ID should not be empty")
	}

	if state.Root == "" {
		return nil, fmt.Errorf("state rootfs should not be empty")
	}
	return &state, nil
}
