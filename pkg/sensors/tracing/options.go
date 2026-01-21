// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/sensors/tracing/common"
)

// Type aliases for backward compatibility
type OverrideMethod = common.OverrideMethod

const (
	OverrideMethodDefault = common.OverrideMethodDefault
	OverrideMethodReturn  = common.OverrideMethodReturn
	OverrideMethodFmodRet = common.OverrideMethodFmodRet
	OverrideMethodInvalid = common.OverrideMethodInvalid
)

type specOptions struct {
	*common.SpecOptions
}

func newDefaultSpecOptions() *specOptions {
	return &specOptions{
		SpecOptions: common.NewDefaultSpecOptions(),
	}
}

func getSpecOptions(specs []v1alpha1.OptionSpec) (*specOptions, error) {
	opts, err := common.GetSpecOptions(specs)
	if err != nil {
		return nil, err
	}
	return &specOptions{SpecOptions: opts}, nil
}

// Helper methods to access fields with old names
func (so *specOptions) policyMode() policyconf.Mode {
	return so.SpecOptions.PolicyMode
}
