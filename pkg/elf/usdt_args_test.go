// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux
// +build amd64,linux

package elf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	spec := UsdtSpec{
		ArgsStr: "-4@-1372(%rbp) -8@(%rbp) 8@%rax -4@$-9",
	}

	err := parseArgs(&spec)

	require.NoError(t, err)
	assert.Equal(t, 4, spec.ArgsCnt)
	assert.Equal(t, UsdtArgTypeRegDeref, spec.Args[0].typ)
	assert.Equal(t, UsdtArgTypeRegDeref, spec.Args[1].typ)
	assert.Equal(t, UsdtArgTypeReg, spec.Args[2].typ)
	assert.Equal(t, UsdtArgTypeConst, spec.Args[3].typ)
}
