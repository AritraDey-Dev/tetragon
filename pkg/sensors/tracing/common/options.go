// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package common

import (
	"fmt"
	"strconv"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyconf"
)

type OverrideMethod int

const (
	KeyOverrideMethod = "override-method"
	ValFmodRet        = "fmod-ret"
	ValOverrideReturn = "override-return"
	KeyPolicyMode     = "policy-mode"
)

const (
	OverrideMethodDefault OverrideMethod = iota
	OverrideMethodReturn
	OverrideMethodFmodRet
	OverrideMethodInvalid
)

func OverrideMethodParse(s string) OverrideMethod {
	switch s {
	case ValFmodRet:
		return OverrideMethodFmodRet
	case ValOverrideReturn:
		return OverrideMethodReturn
	default:
		return OverrideMethodInvalid
	}
}

type SpecOptions struct {
	DisableKprobeMulti bool
	DisableUprobeMulti bool
	OverrideMethod     OverrideMethod
	PolicyMode         policyconf.Mode
}

type opt struct {
	set func(val string, options *SpecOptions) error
}

func NewDefaultSpecOptions() *SpecOptions {
	return &SpecOptions{
		DisableKprobeMulti: false,
		OverrideMethod:     OverrideMethodDefault,
	}
}

var opts = map[string]opt{
	option.KeyDisableKprobeMulti: {
		set: func(str string, options *SpecOptions) (err error) {
			options.DisableKprobeMulti, err = strconv.ParseBool(str)
			return err
		},
	},
	option.KeyDisableUprobeMulti: {
		set: func(str string, options *SpecOptions) (err error) {
			options.DisableUprobeMulti, err = strconv.ParseBool(str)
			return err
		},
	},
	KeyOverrideMethod: {
		set: func(str string, options *SpecOptions) (err error) {
			m := OverrideMethodParse(str)
			if m == OverrideMethodInvalid {
				return fmt.Errorf("invalid override method: '%s'", str)
			}
			options.OverrideMethod = m
			return nil
		},
	},
	KeyPolicyMode: {
		set: func(str string, options *SpecOptions) (err error) {
			mode, err := policyconf.ParseMode(str)
			if err != nil {
				return err
			}
			options.PolicyMode = mode
			return nil
		},
	},
}

func GetSpecOptions(specs []v1alpha1.OptionSpec) (*SpecOptions, error) {
	options := NewDefaultSpecOptions()
	for _, spec := range specs {
		opt, ok := opts[spec.Name]
		if ok {
			if err := opt.set(spec.Value, options); err != nil {
				return nil, fmt.Errorf("failed to set option %s: %w", spec.Name, err)
			}
			logger.GetLogger().Info(fmt.Sprintf("Set option %s = %s", spec.Name, spec.Value))
		}
	}
	return options, nil
}
