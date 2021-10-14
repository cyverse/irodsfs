package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/cyverse/irodsfs/pkg/commons"
	"github.com/cyverse/irodsfs/pkg/irodsfs"
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

func main() {
	log.SetLevel(log.DebugLevel)

	// check if this is subprocess running in the background
	isChildProc := false

	childProcessArgument := fmt.Sprintf("-%s", ChildProcessArgument)
	for _, arg := range os.Args[1:] {
		if arg == childProcessArgument {
			// background
			isChildProc = true
			break
		}
	}

	if isChildProc {
		// child process
		childMain()
	} else {
		// parent process
		parentMain()
	}
}

// RunFSDaemon runs irodsfs as a daemon
func RunFSDaemon(irodsfsExec string, config *commons.Config) error {
	return parentRun(irodsfsExec, config)
}

// parentRun executes irodsfs with the config given
func parentRun(irodsfsExec string, config *commons.Config) error {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "parentRun",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := config.Validate()
	if err != nil {
		logger.WithError(err).Error("invalid argument")
		return err
	}

	if !config.Foreground {
		// run child process in background and pass parameters via stdin PIPE
		// receives result from the child process
		logger.Info("Running the process in the background mode")
		childProcessArgument := fmt.Sprintf("-%s", ChildProcessArgument)
		cmd := exec.Command(irodsfsExec, childProcessArgument)
		subStdin, err := cmd.StdinPipe()
		if err != nil {
			logger.WithError(err).Error("failed to communicate to background process")
			return err
		}

		subStdout, err := cmd.StdoutPipe()
		if err != nil {
			logger.WithError(err).Error("failed to communicate to background process")
			return err
		}

		cmd.Stderr = cmd.Stdout

		err = cmd.Start()
		if err != nil {
			logger.WithError(err).Errorf("failed to start a child process")
			return err
		}

		logger.Infof("Process id = %d", cmd.Process.Pid)

		logger.Info("Sending configuration data")
		configBytes, err := yaml.Marshal(config)
		if err != nil {
			logger.WithError(err).Error("failed to serialize configuration")
			return err
		}

		// send it to child
		_, err = io.WriteString(subStdin, string(configBytes))
		if err != nil {
			logger.WithError(err).Error("failed to communicate to background process")
			return err
		}
		subStdin.Close()
		logger.Info("Successfully sent configuration data to background process")

		childProcessFailed := false

		// receive output from child
		subOutputScanner := bufio.NewScanner(subStdout)
		for {
			if subOutputScanner.Scan() {
				errMsg := strings.TrimSpace(subOutputScanner.Text())
				if errMsg == InterProcessCommunicationFinishSuccess {
					logger.Info("Successfully started background process")
					break
				} else if errMsg == InterProcessCommunicationFinishError {
					logger.Error("failed to start background process")
					childProcessFailed = true
					break
				} else {
					logger.Info(errMsg)
				}
			} else {
				// check err
				if subOutputScanner.Err() != nil {
					logger.Error(subOutputScanner.Err().Error())
					childProcessFailed = true
					break
				}
			}
		}

		subStdout.Close()

		if childProcessFailed {
			return fmt.Errorf("failed to start background process")
		}
	} else {
		// foreground
		err = run(config, false)
		if err != nil {
			logger.WithError(err).Error("failed to run iRODS FUSE Lite")
			return err
		}
	}

	return nil
}

// parentMain handles command-line parameters and run parent process
func parentMain() {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "parentMain",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// parse argument
	config, logWriter, err, exit := processArguments()
	if err != nil {
		logger.WithError(err).Error("failed to process arguments")
		if exit {
			logger.Fatal(err)
		}
	}
	if exit {
		os.Exit(0)
	}

	// check fuse
	fuseCheckResult := checkFuse()
	switch fuseCheckResult {
	case CheckFUSEStatusFound:
		// okay
		logger.Info("Found FUSE Device. Starting iRODS FUSE Lite.")
	case CheckFUSEStatusUnknown:
		// try to go
		logger.Info("It is not sure whether FUSE is running. Starting iRODS FUSE Lite, anyway.")
	case CheckFUSEStatusNotFound:
		logger.Fatal("FUSE is not running. Terminating iRODS FUSE Lite.")
	case CheckFUSEStatusCannotRun:
		logger.Fatal("FUSE is not supported. Terminating iRODS FUSE Lite.")
	}

	// run
	err = parentRun(os.Args[0], config)
	if err != nil {
		logger.WithError(err).Error("failed to run the foreground process")
		logger.Fatal(err)
	}

	// clean up
	if logWriter != nil {
		logWriter.Close()
	}

	os.Exit(0)
}

// childMain runs child process
func childMain() {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "childMain",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// output to default log file for child process
	childLogWriter := getLogWriter(commons.LogFilePathChildDefault)
	log.SetOutput(childLogWriter)

	logger.Info("Start background process")

	logger.Info("Check STDIN to communicate to parent process")
	// read from stdin
	_, err := os.Stdin.Stat()
	if err != nil {
		logger.WithError(err).Error("failed to communicate to foreground process")
		fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		os.Exit(1)
	}

	logger.Info("Reading configuration from STDIN")
	configBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		logger.WithError(err).Error("failed to read configuration")
		fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		os.Exit(1)
	}
	logger.Info("Successfully read configuration from STDIN")

	config, err := commons.NewConfigFromYAML(configBytes)
	if err != nil {
		logger.WithError(err).Error("failed to read configuration")
		fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		os.Exit(1)
	}

	// output to log file
	var logWriter io.WriteCloser
	if len(config.LogPath) > 0 && config.LogPath != "-" {
		logWriter = getLogWriter(config.LogPath)
		log.SetOutput(logWriter)
	}

	err = config.Validate()
	if err != nil {
		logger.WithError(err).Error("invalid configuration")
		fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		os.Exit(1)
	}

	logger.Info("Run background process")

	// background
	err = run(config, true)
	if err != nil {
		logger.WithError(err).Error("failed to run iRODS FUSE Lite")
		os.Exit(1)
	}

	if logWriter != nil {
		logWriter.Close()
		// delete if it is successful close
		os.Remove(config.LogPath)
	}
}

// run runs irodsfs
func run(config *commons.Config, isChildProcess bool) error {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "run",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	logger.Info("Creating a File System")
	fs, err := irodsfs.NewFileSystem(config)
	if err != nil {
		logger.WithError(err).Error("failed to create filesystem")
		if isChildProcess {
			fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		}
		return err
	}

	logger.Info("Successfully created a File System")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT)

	go func() {
		receivedSignal := <-signalChan

		logger.Infof("received signal (%s), terminating iRODS FUSE Lite", receivedSignal.String())
		if isChildProcess {
			fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		}

		fs.StopFuse()
	}()

	logger.Info("Connecting to FUSE")

	err = fs.ConnectToFuse()
	if err != nil {
		logger.WithError(err).Error("failed to connect to FUSE, terminating iRODS FUSE Lite")

		if isChildProcess {
			fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		}

		fs.Destroy()
		return err
	}

	if isChildProcess {
		fmt.Fprintln(os.Stdout, InterProcessCommunicationFinishSuccess)
		if config.LogPath == "-" || len(config.LogPath) == 0 {
			// stderr is not a local file, so is closed by parent
			var nilWriter NilWriter
			log.SetOutput(&nilWriter)
		}
	}

	err = fs.StartFuse()
	if err != nil {
		logger.WithError(err).Error("failed to start FUSE, terminating iRODS FUSE Lite")
		fs.Destroy()
		return err
	}

	// returns if mount fails, or stopped.
	logger.Info("FUSE stopped, terminating iRODS FUSE Lite")
	fs.Destroy()
	return nil
}
