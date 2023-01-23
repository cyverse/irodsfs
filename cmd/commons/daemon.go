package commons

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/cyverse/irodsfs/commons"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
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
	fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
}

func ReportChildProcessStartSuccessfully() {
	fmt.Fprintln(os.Stdout, InterProcessCommunicationFinishSuccess)
}

func SetNilLogWriter() {
	var nilWriter NilWriter
	log.SetOutput(&nilWriter)
}

func RunChildProcess(serverExec string) (io.WriteCloser, io.ReadCloser, error) {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "RunChildProcess",
	})

	// run child process in background and pass parameters via stdin PIPE
	// receives result from the child process
	logger.Info("Running the child process in the background mode")
	childProcessArgument := fmt.Sprintf("--%s", ChildProcessArgument)
	cmd := exec.Command(serverExec, childProcessArgument)
	childStdin, err := cmd.StdinPipe()
	if err != nil {
		logger.WithError(err).Error("failed to get the child process's STDIN")
		return nil, nil, err
	}

	childStdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.WithError(err).Error("failed to get the child process's STDOUT")
		return nil, nil, err
	}

	cmd.Stderr = cmd.Stdout

	// start
	err = cmd.Start()
	if err != nil {
		logger.WithError(err).Errorf("failed to start the child process")
		return nil, nil, err
	}

	logger.Infof("Child process id = %d", cmd.Process.Pid)
	return childStdin, childStdout, nil

}

func ParentProcessSendConfigViaSTDIN(config *commons.Config, stdin io.WriteCloser, stdout io.ReadCloser) error {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "ParentProcessSendConfigViaSTDIN",
	})

	logger.Info("Sending configuration via STDIN")
	configBytes, err := yaml.Marshal(config)
	if err != nil {
		logger.WithError(err).Error("failed to serialize configuration")
		return err
	}

	// send it to child
	_, err = io.WriteString(stdin, string(configBytes))
	if err != nil {
		logger.WithError(err).Error("failed to send via STDIN")
		return err
	}

	stdin.Close()

	logger.Info("Successfully sent configuration to STDIN")

	// receive output from child
	childProcessFailed := false
	childOutputScanner := bufio.NewScanner(stdout)
	for {
		if childOutputScanner.Scan() {
			errMsg := strings.TrimSpace(childOutputScanner.Text())
			if errMsg == InterProcessCommunicationFinishSuccess {
				logger.Info("Successfully started child process")
				break
			} else if errMsg == InterProcessCommunicationFinishError {
				logger.Error("failed to start child process")
				childProcessFailed = true
				break
			} else {
				logger.Info(errMsg)
			}
		} else {
			// check err
			if childOutputScanner.Err() != nil {
				logger.Error(childOutputScanner.Err().Error())
				childProcessFailed = true
				break
			}
		}
	}

	stdout.Close()

	if childProcessFailed {
		return fmt.Errorf("failed to start child process")
	}

	return nil
}

func ChildProcessReadConfigViaSTDIN() (*commons.Config, io.WriteCloser, error) {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "ChildProcessReadConfigViaSTDIN",
	})

	// read from stdin
	logger.Info("Check STDIN to communicate to other process")
	_, err := os.Stdin.Stat()
	if err != nil {
		logger.WithError(err).Error("failed to read from STDIN")
		return nil, nil, err
	}

	logger.Info("Reading configuration from STDIN")
	configBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		logger.WithError(err).Error("failed to read configuration")
		return nil, nil, err
	}
	logger.Info("Successfully read configuration from STDIN")

	config, err := commons.NewConfigFromYAML(configBytes)
	if err != nil {
		logger.WithError(err).Error("failed to read configuration")
		return nil, nil, err
	}

	if config.Debug {
		log.SetLevel(log.DebugLevel)
	}

	err = config.Validate()
	if err != nil {
		logger.Error(err)
		return nil, nil, err
	}

	err = config.MakeLogDir()
	if err != nil {
		logger.Error(err)
		return nil, nil, err
	}

	// output to log file
	logFilePath := config.GetLogFilePath()
	if len(logFilePath) > 0 && logFilePath != "-" {
		logWriter, childLogFilePath := getLogWriterForChildProcess(logFilePath)
		log.SetOutput(logWriter)

		logger.Infof("Logging to %s", childLogFilePath)
		return config, logWriter, nil
	} else {
		var nilWriter NilWriter
		log.SetOutput(&nilWriter)
		return config, &nilWriter, nil
	}
}
