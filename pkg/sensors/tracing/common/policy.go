// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package common

import (
	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/policystats"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type PolicyInfo struct {
	Name          string
	Namespace     string
	PolicyID      policyfilter.PolicyID
	CustomHandler eventhandler.Handler
	PolicyConf    *program.Map
	PolicyStats   *program.Map
	SpecOpts      *SpecOptions
}

func NewPolicyInfo(
	policy tracingpolicy.TracingPolicy,
	policyID policyfilter.PolicyID,
) (*PolicyInfo, error) {
	namespace := ""
	if tpn, ok := policy.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpn.TpNamespace()
	}

	return NewPolicyInfoFromSpec(
		namespace,
		policy.TpName(),
		policyID,
		policy.TpSpec(),
		eventhandler.GetCustomEventhandler(policy),
	)
}

func HasEnforcementActions(spec *v1alpha1.TracingPolicySpec) bool {
	for _, kprobe := range spec.KProbes {
		if selectors.HasEnforcementAction(kprobe.Selectors) || selectors.HasOverride(kprobe.Selectors) {
			return true
		}
	}

	for _, uprobe := range spec.UProbes {
		if selectors.HasEnforcementAction(uprobe.Selectors) || selectors.HasOverride(uprobe.Selectors) {
			return true
		}
	}

	for _, tp := range spec.Tracepoints {
		if selectors.HasEnforcementAction(tp.Selectors) || selectors.HasOverride(tp.Selectors) {
			return true
		}
	}

	for _, lsm := range spec.LsmHooks {
		if selectors.HasEnforcementAction(lsm.Selectors) || selectors.HasOverride(lsm.Selectors) {
			return true
		}
	}

	for _, usdt := range spec.Usdts {
		if selectors.HasEnforcementAction(usdt.Selectors) || selectors.HasOverride(usdt.Selectors) {
			return true
		}
	}

	return false
}

func NewPolicyInfoFromSpec(
	namespace, name string,
	policyID policyfilter.PolicyID,
	spec *v1alpha1.TracingPolicySpec,
	customHandler eventhandler.Handler,
) (*PolicyInfo, error) {
	opts, err := GetSpecOptions(spec.Options)
	if err != nil {
		return nil, err
	}

	// If enforcement is not allowed, force monitor only
	if !HasEnforcementActions(spec) {
		opts.PolicyMode = policyconf.MonitorOnlyMode
	}

	return &PolicyInfo{
		Name:          name,
		Namespace:     namespace,
		PolicyID:      policyID,
		CustomHandler: customHandler,
		PolicyConf:    nil,
		PolicyStats:   nil,
		SpecOpts:      opts,
	}, nil
}

func (pi *PolicyInfo) PolicyStatsMap(prog *program.Program) *program.Map {
	if pi.PolicyStats != nil {
		return program.MapUserFrom(pi.PolicyStats)
	}
	pi.PolicyStats = program.MapBuilderPolicy(policystats.PolicyStatsMapName, prog)
	return pi.PolicyStats
}

func (pi *PolicyInfo) PolicyConfMap(prog *program.Program) *program.Map {
	if pi.PolicyConf != nil {
		return program.MapUserFrom(pi.PolicyConf)
	}
	pi.PolicyConf = program.MapBuilderPolicy(policyconf.PolicyConfMapName, prog)
	prog.MapLoad = append(prog.MapLoad, &program.MapLoad{
		Name: policyconf.PolicyConfMapName,
		Load: func(m *ebpf.Map, _ string) error {
			mode := policyconf.EnforceMode
			if pi.SpecOpts != nil {
				mode = pi.SpecOpts.PolicyMode
			}
			conf := policyconf.PolicyConf{
				Mode: mode,
			}
			key := uint32(0)
			return m.Update(key, &conf, ebpf.UpdateAny)
		},
	})
	return pi.PolicyConf
}
