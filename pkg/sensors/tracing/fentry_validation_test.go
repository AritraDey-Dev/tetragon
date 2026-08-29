// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/policyfilter"
)

func fentrySpecWithAction(action string) *v1alpha1.TracingPolicySpec {
	return &v1alpha1.TracingPolicySpec{
		Fentries: []v1alpha1.KProbeSpec{{
			Call:    "sys_openat",
			Syscall: true,
			Selectors: []v1alpha1.KProbeSelector{{
				MatchActions: []v1alpha1.ActionSelector{{Action: action}},
			}},
		}},
	}
}

// Undetected enforcement actions silently downgrade the policy to monitor only.
func TestFentryEnforcementActionsDetected(t *testing.T) {
	for _, action := range []string{"Sigkill", "Signal", "NotifyEnforcer", "Override"} {
		t.Run(action, func(t *testing.T) {
			spec := fentrySpecWithAction(action)
			require.True(t, hasEnforcementActions(spec),
				"enforcement action %q in a fentries section was not detected", action)

			polInfo, err := newPolicyInfoFromSpec("", "fentry-enforce", policyfilter.NoFilterID, spec, nil)
			require.NoError(t, err)
			require.Equal(t, policyconf.EnforceMode, polInfo.specOpts.policyMode,
				"policy with a %q action must not be forced to monitor only", action)
		})
	}
}

func TestFentryWithoutEnforcementIsMonitorOnly(t *testing.T) {
	spec := fentrySpecWithAction("Post")
	require.False(t, hasEnforcementActions(spec))

	polInfo, err := newPolicyInfoFromSpec("", "fentry-monitor", policyfilter.NoFilterID, spec, nil)
	require.NoError(t, err)
	require.Equal(t, policyconf.MonitorOnlyMode, polInfo.specOpts.policyMode)
}
func TestFentryEnforcementActionsAccepted(t *testing.T) {
	// These compile to a no-op for GENERIC_FENTRY, so they must be rejected
	// rather than silently doing nothing.
	for _, action := range []string{"Override", "NotifyEnforcer", "Set"} {
		t.Run(action+" is rejected", func(t *testing.T) {
			err := checkFentryEnforcement(fentrySpecWithAction(action).Fentries)
			require.Error(t, err)
		})
	}

	for _, action := range []string{"Sigkill", "Signal", "Post"} {
		t.Run(action+" is accepted", func(t *testing.T) {
			require.NoError(t, checkFentryEnforcement(fentrySpecWithAction(action).Fentries))
		})
	}
}
