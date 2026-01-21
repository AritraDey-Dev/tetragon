// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kprobe

import (
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
)

type observerKprobeSensor struct {
	name string
}

func (k *observerKprobeSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	// TODO: Move loadGenericKprobeSensor implementation here in next commit
	// For now, this is a placeholder
	_ = args
	return nil
}

func init() {
	kprobe := &observerKprobeSensor{
		name: "kprobe sensor",
	}
	sensors.RegisterProbeType("generic_kprobe", kprobe)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_GENERIC_KPROBE, HandleGenericKprobe)
}
