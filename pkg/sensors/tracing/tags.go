// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"github.com/cilium/tetragon/pkg/sensors/tracing/common"
)

// Constants and errors for backward compatibility
const (
	TpMaxTags   = common.TpMaxTags
	TpMinTagLen = common.TpMinTagLen
	TpMaxTagLen = common.TpMaxTagLen
)

var (
	ErrTagsSyntaxLong = common.ErrTagsSyntaxLong
	ErrTagSyntaxShort = common.ErrTagSyntaxShort
)

func GetPolicyTags(tags []string) ([]string, error) {
	return common.GetPolicyTags(tags)
}
