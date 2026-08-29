// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

type observerFentrySensor struct {
	name string
}

func init() {
	fentry := &observerFentrySensor{
		name: "fentrry sensor",
	}
	sensors.RegisterProbeType("generic_fentry", fentry)
}

func createGenericFentrySensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	polInfo *policyInfo,
	valInfo []*kpValidateInfo,
) (*sensors.Sensor, error) {

	if err := checkFentryEnforcement(spec.Fentries); err != nil {
		return nil, err
	}

	return createGenericKprobeSensor(spec, name, polInfo, valInfo, fentry)
}

// Actions that compile to a no-op for GENERIC_FENTRY, so accepting them would
// silently do nothing:
//
//	override        bpf_override_return() is kprobe only
//	notifyEnforcer  do_action_notify_enforcer() is gated on
//	                GENERIC_TRACEPOINT || GENERIC_KPROBE in types/basic.h
//	set             do_set_action() is gated on GENERIC_USDT in generic_calls.h
//
// sigkill and signal go through do_action_signal(), which is only gated on
// __LARGE_BPF_PROG, so they work for fentry.
func checkFentryEnforcement(fentries []v1alpha1.KProbeSpec) error {
	for i := range fentries {
		sel := fentries[i].Selectors
		switch {
		case selectors.HasOverride(sel):
			return errors.New("the override action is not supported for fentry, use a kprobe instead")
		case selectors.HasNotifyEnforcerAction(sel):
			return errors.New("the notifyEnforcer action is not supported for fentry, use a kprobe instead")
		case selectors.HasSet(sel):
			return errors.New("the set action is not supported for fentry, it is only implemented for usdt")
		}
	}
	return nil
}

func (k *observerFentrySensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadGenericFentrySensor(args.BPFDir, args.Load, args.Maps, args.Verbose)
}

func loadGenericFentrySensor(bpfDir string, load *program.Program, maps []*program.Map, verbose int) error {
	if id, ok := load.LoaderData.(idtable.EntryID); ok {
		return loadSingleKprobeSensor(id, bpfDir, load, maps, verbose, true)
	}
	return fmt.Errorf("invalid loadData type: expecting idtable.EntryID and got: %T (%v)",
		load.LoaderData, load.LoaderData)
}
