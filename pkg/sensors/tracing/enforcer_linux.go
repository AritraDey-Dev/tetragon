// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/tracing/common"
)

func enforcerMapsUser(load *program.Program) []*program.Map {
	return common.EnforcerMapsUser(load)
}
