// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/tracing/common"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type policyInfo struct {
	name          string
	namespace     string
	policyID      policyfilter.PolicyID
	customHandler eventhandler.Handler
	policyConf    *program.Map
	policyStats   *program.Map
	specOpts      *specOptions
}

func newPolicyInfo(
	policy tracingpolicy.TracingPolicy,
	policyID policyfilter.PolicyID,
) (*policyInfo, error) {
	commonInfo, err := common.NewPolicyInfo(policy, policyID)
	if err != nil {
		return nil, err
	}
	return convertPolicyInfo(commonInfo)
}

func hasEnforcementActions(spec *v1alpha1.TracingPolicySpec) bool {
	return common.HasEnforcementActions(spec)
}

func newPolicyInfoFromSpec(
	namespace, name string,
	policyID policyfilter.PolicyID,
	spec *v1alpha1.TracingPolicySpec,
	customHandler eventhandler.Handler,
) (*policyInfo, error) {
	commonInfo, err := common.NewPolicyInfoFromSpec(namespace, name, policyID, spec, customHandler)
	if err != nil {
		return nil, err
	}
	return convertPolicyInfo(commonInfo)
}

func convertPolicyInfo(commonInfo *common.PolicyInfo) (*policyInfo, error) {
	// Convert common.SpecOptions to local specOptions
	var localOpts *specOptions
	if commonInfo.SpecOpts != nil {
		localOpts = &specOptions{SpecOptions: commonInfo.SpecOpts}
	}

	return &policyInfo{
		name:          commonInfo.Name,
		namespace:     commonInfo.Namespace,
		policyID:      commonInfo.PolicyID,
		customHandler: commonInfo.CustomHandler,
		policyConf:    commonInfo.PolicyConf,
		policyStats:   commonInfo.PolicyStats,
		specOpts:      localOpts,
	}, nil
}

func (pi *policyInfo) policyStatsMap(prog *program.Program) *program.Map {
	// Convert to common.PolicyInfo temporarily to use common method
	commonInfo := &common.PolicyInfo{
		Name:          pi.name,
		Namespace:     pi.namespace,
		PolicyID:      pi.policyID,
		CustomHandler: pi.customHandler,
		PolicyConf:    pi.policyConf,
		PolicyStats:   pi.policyStats,
		SpecOpts:      nil,
	}
	if pi.specOpts != nil {
		commonInfo.SpecOpts = pi.specOpts.SpecOptions
	}
	result := commonInfo.PolicyStatsMap(prog)
	pi.policyStats = result
	return result
}

func (pi *policyInfo) policyConfMap(prog *program.Program) *program.Map {
	// Convert to common.PolicyInfo temporarily to use common method
	commonInfo := &common.PolicyInfo{
		Name:          pi.name,
		Namespace:     pi.namespace,
		PolicyID:      pi.policyID,
		CustomHandler: pi.customHandler,
		PolicyConf:    pi.policyConf,
		PolicyStats:   pi.policyStats,
		SpecOpts:      nil,
	}
	if pi.specOpts != nil {
		commonInfo.SpecOpts = pi.specOpts.SpecOptions
	}
	result := commonInfo.PolicyConfMap(prog)
	pi.policyConf = result
	return result
}

func (h policyHandler) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	policyID policyfilter.PolicyID,
) (sensors.SensorIface, error) {

	spec := policy.TpSpec()
	sections := 0
	if len(spec.KProbes) > 0 {
		sections++
	}
	if len(spec.Tracepoints) > 0 {
		sections++
	}
	if len(spec.LsmHooks) > 0 {
		sections++
	}
	if len(spec.UProbes) > 0 {
		sections++
	}
	if len(spec.Usdts) > 0 {
		sections++
	}
	if sections > 1 {
		return nil, errors.New("tracing policies with multiple sections of kprobes, tracepoints, lsm hooks, uprobes or usdts are currently not supported")
	}

	polInfo, err := newPolicyInfo(policy, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse options: %w", err)
	}

	if len(spec.KProbes) > 0 {
		name := "generic_kprobe"
		log := logger.GetLogger().With(
			"policy", tracingpolicy.TpLongname(policy),
			"sensor", name,
		)
		validateInfo, err := preValidateKprobes(log, spec.KProbes, spec.Lists, spec.Enforcers)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		// if all kprobes where ignored, do not load anything. This is equivalent with
		// having a policy with an empty kprobe: section
		if allKprobesIgnored(validateInfo) {
			return nil, nil
		}
		return createGenericKprobeSensor(spec, name, polInfo, validateInfo)
	}
	if len(spec.Tracepoints) > 0 {
		return createGenericTracepointSensor(spec, "generic_tracepoint", polInfo)
	}
	if len(spec.LsmHooks) > 0 {
		return createGenericLsmSensor(spec, "generic_lsm", polInfo)
	}
	if len(spec.UProbes) > 0 {
		return createGenericUprobeSensor(spec, "generic_uprobe", polInfo)
	}
	if len(spec.Usdts) > 0 {
		return createGenericUsdtSensor(spec, "generic_usdt", polInfo)
	}
	return nil, nil
}
