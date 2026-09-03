package main

import (
	"os"
	"reflect"
	"syscall"
	"testing"
)

func TestWaitForShutdownEventDetectsExternalUnmount(t *testing.T) {
	fuseExited := make(chan struct{})
	close(fuseExited)

	if reason := waitForShutdownEvent(fuseExited, make(chan os.Signal)); reason != shutdownByExternalUnmount {
		t.Fatalf("shutdown reason = %v, want shutdownByExternalUnmount", reason)
	}
}

func TestWaitForShutdownEventDetectsSignal(t *testing.T) {
	signalChannel := make(chan os.Signal, 1)
	signalChannel <- syscall.SIGTERM

	if reason := waitForShutdownEvent(make(chan struct{}), signalChannel); reason != shutdownBySignal {
		t.Fatalf("shutdown reason = %v, want shutdownBySignal", reason)
	}
}

func TestFinishManagedFilesystemAfterExternalUnmountOnlyReleases(t *testing.T) {
	var calls []string
	filesystem := &managedFilesystem{
		shutdown: func() { calls = append(calls, "shutdown") },
		release:  func() { calls = append(calls, "release") },
	}

	finishManagedFilesystem(filesystem, shutdownByExternalUnmount)

	if want := []string{"release"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("cleanup calls = %v, want %v", calls, want)
	}
}

func TestFinishManagedFilesystemAfterSignalUnmountsThenReleases(t *testing.T) {
	var calls []string
	filesystem := &managedFilesystem{
		shutdown: func() { calls = append(calls, "shutdown") },
		release:  func() { calls = append(calls, "release") },
	}

	finishManagedFilesystem(filesystem, shutdownBySignal)

	if want := []string{"shutdown", "release"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("cleanup calls = %v, want %v", calls, want)
	}
}
