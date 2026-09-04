package main

import (
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/cockroachdb/errors"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
)

func TestExitCodeForError(t *testing.T) {
	if got := exitCodeForError(errors.New("ordinary failure")); got != exitCodeGeneralFailure {
		t.Fatalf("ordinary error exit code = %d, want %d", got, exitCodeGeneralFailure)
	}
	if got := exitCodeForError(&exitCodeError{err: errors.New("invalid config"), code: exitCodeConfigurationInvalid}); got != exitCodeConfigurationInvalid {
		t.Fatalf("configuration error exit code = %d, want %d", got, exitCodeConfigurationInvalid)
	}
}

func TestInitialFilesystemErrorClassifiesAuthenticationFailure(t *testing.T) {
	authErr := errors.Wrap(irodsclient_types.NewAuthError(&irodsclient_types.IRODSAccount{}), "filesystem initialization failed")
	if got := exitCodeForError(initialFilesystemError(authErr)); got != exitCodeAuthenticationFailed {
		t.Fatalf("authentication error exit code = %d, want %d", got, exitCodeAuthenticationFailed)
	}
	if got := exitCodeForError(initialFilesystemError(errors.New("connection refused"))); got != exitCodeGeneralFailure {
		t.Fatalf("non-authentication error exit code = %d, want %d", got, exitCodeGeneralFailure)
	}
}

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
