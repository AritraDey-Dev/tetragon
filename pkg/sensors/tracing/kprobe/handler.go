// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kprobe

import (
	"bytes"

	"github.com/cilium/tetragon/pkg/observer"
)

// HandleGenericKprobe handles generic kprobe events
// TODO: Move full implementation from generickprobe.go in next commit
// For now, this is a placeholder that will be implemented in the next commit
func HandleGenericKprobe(r *bytes.Reader) ([]observer.Event, error) {
	// Implementation will be moved here in next commit
	// For now, call the exported function from tracing package
	_ = r
	return nil, nil
}
