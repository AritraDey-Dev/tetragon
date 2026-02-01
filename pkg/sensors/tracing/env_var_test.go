// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
)

func TestEnvVarExport(t *testing.T) {
	// 1. Enable global env var collection (simulating global config)
	// We need to set this before any process starts so execve listener picks it up
	option.Config.EnableProcessEnvironmentVariables = true
	defer func() {
		option.Config.EnableProcessEnvironmentVariables = false
	}()

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	// 2. Create a dummy test command that will be executed
	targetEnvKey := "TETRAGON_TEST_VAR"
	targetEnvVal := "found_it"

	// 3. Define Policy
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	testFile := filepath.Join(t.TempDir(), "testfile")
	os.Create(testFile)

	myCmd := "cat"

	tracingPolicy := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "env-var-test"
spec:
  kprobes:
  - call: "sys_openat"
    syscall: true
    args:
    - index: 1
      type: "string"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "` + testFile + `"
    envs:
    - "` + targetEnvKey + `"
`

	configHook := []byte(tracingPolicy)
	err := os.WriteFile(testConfigFile, configHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	// 4. Start Observer
	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	// 5. Run the command with the custom environment environment variable
	// We use exec.Command to launch a subprocess.
	cmd := exec.Command(myCmd, testFile)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", targetEnvKey, targetEnvVal))

	if err := cmd.Run(); err != nil {
		t.Fatalf("cmd.Run() failed: %v", err)
	}

	// 6. Check for the event with the env var
	// We expect a ProcessKprobe event for sys_openat
	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Suffix("sys_openat")).
		WithEnvs(ec.NewEnvVarListMatcher().
			WithOperator(lc.Subset).
			WithValues(
				ec.NewEnvVarChecker().
					WithKey(sm.Full(targetEnvKey)).
					WithValue(sm.Full(targetEnvVal)),
			))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}
