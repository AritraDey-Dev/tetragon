package progs

import (
	"context"
	"testing"
	"time"


)

func TestPingRepro(t *testing.T) {
	// Simulate timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	pt := StartTester(t, ctx)
	time.Sleep(10 * time.Millisecond) // Wait for timeout
	err := pt.Ping()
	if err == nil {
		t.Log("Ping succeeded unexpectedly")
	} else {
		t.Logf("Ping failed as expected: %v", err)
	}
	err = pt.Stop()
	if err == nil {
		t.Log("Stop succeeded unexpectedly")
	} else {
		t.Logf("Stop failed as expected: %v", err)
	}
}
