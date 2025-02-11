package commons

import (
	"fmt"
	"os"
)

const (
	// InterProcessCommunicationFinishSuccess is the message that parent process receives when child process is executed successfully
	InterProcessCommunicationFinishSuccess string = "<<COMMUNICATION_CLOSE_SUCCESS>>"
	// InterProcessCommunicationFinishError is the message that parent process receives when child process fails to run
	InterProcessCommunicationFinishError string = "<<COMMUNICATION_CLOSE_ERROR>>"
)

// NilWriter drains output
type NilWriter struct{}

// Write does nothing
func (w *NilWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (w *NilWriter) Close() (err error) {
	return nil
}

func ReportChildProcessError() {
	fmt.Fprintln(os.Stdout, InterProcessCommunicationFinishError)
}

func ReportChildProcessStartSuccessfully() {
	fmt.Fprintln(os.Stdout, InterProcessCommunicationFinishSuccess)
}
