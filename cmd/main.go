package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cyverse/irodsfs/pkg/irodsfs"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	InterProcessCommunicationFinishSuccess string = "<<COMMUNICATION_CLOSE_SUCCESS>>"
	InterProcessCommunicationFinishError   string = "<<COMMUNICATION_CLOSE_ERROR>>"
)

type NilWriter struct{}

// Write does nothing
func (w *NilWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func main() {
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
		childMain()
	} else {
		parentMain()
	}
}

func RunFSDaemon(irodsfsExec string, config *irodsfs.Config) error {
	return parentRun(irodsfsExec, config)
}

func parentRun(irodsfsExec string, config *irodsfs.Config) error {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "parentRun",
	})

	err := config.Validate()
	if err != nil {
		logger.WithError(err).Error("Argument validation error")
		return err
	}

	if !config.Foreground {
		// run the program in background
		logger.Info("Running the process in the background mode")
		childProcessArgument := fmt.Sprintf("-%s", ChildProcessArgument)
		cmd := exec.Command(irodsfsExec, childProcessArgument)
		subStdin, err := cmd.StdinPipe()
		if err != nil {
			logger.WithError(err).Error("Could not communicate to background process")
			return err
		}

		subStdout, err := cmd.StdoutPipe()
		if err != nil {
			logger.WithError(err).Error("Could not communicate to background process")
			return err
		}

		cmd.Stderr = cmd.Stdout

		err = cmd.Start()
		if err != nil {
			logger.WithError(err).Errorf("Could not start a child process")
			return err
		}

		logger.Infof("Process id = %d", cmd.Process.Pid)

		logger.Info("Sending configuration data")
		configBytes, err := yaml.Marshal(config)
		if err != nil {
			logger.WithError(err).Error("Could not serialize configuration")
			return err
		}

		// send it to child
		_, err = io.WriteString(subStdin, string(configBytes))
		if err != nil {
			logger.WithError(err).Error("Could not communicate to background process")
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
					logger.Error("Failed to start background process")
					childProcessFailed = true
					break
				} else {
					fmt.Fprintln(os.Stderr, errMsg)
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
			return fmt.Errorf("Failed to start background process")
		}
	} else {
		// foreground
		err = run(config, false)
		if err != nil {
			logger.WithError(err).Error("Could not run irodsfs")
			return err
		}
	}

	return nil
}

func parentMain() {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "parentMain",
	})

	// parse argument
	config, err, exit := processArguments()
	if err != nil {
		logger.WithError(err).Error("Error occurred while processing arguments")
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
		logger.WithError(err).Error("Error occurred while running parent process")
		logger.Fatal(err)
	}

	os.Exit(0)
}

func childMain() {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "childMain",
	})

	logger.Info("Start background process")

	// read from stdin
	_, err := os.Stdin.Stat()
	if err != nil {
		logger.WithError(err).Error("Could not communicate to foreground process")
		fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		os.Exit(1)
	}

	configBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		logger.WithError(err).Error("Could not read configuration")
		fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		os.Exit(1)
	}

	config, err := irodsfs.NewConfigFromYAML(configBytes)
	if err != nil {
		logger.WithError(err).Error("Could not read configuration")
		fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		os.Exit(1)
	}

	// output to default log
	if len(config.LogPath) > 0 {
		logFile, err := os.OpenFile(config.LogPath, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			logger.WithError(err).Error("Could not create log file")
			fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
			os.Exit(1)
		} else {
			log.SetOutput(logFile)
		}
	}

	err = config.Validate()
	if err != nil {
		logger.WithError(err).Error("Argument validation error")
		fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		os.Exit(1)
	}

	// background
	err = run(config, true)
	if err != nil {
		logger.WithError(err).Error("Could not run irodsfs")
		os.Exit(1)
	}
}

func run(config *irodsfs.Config, isChildProcess bool) error {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "run",
	})

	fs, err := irodsfs.NewFileSystem(config)
	if err != nil {
		logger.WithError(err).Error("Could not create filesystem")
		if isChildProcess {
			fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		}
		return err
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT)

	go func() {
		<-signalChan
		if isChildProcess {
			fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		}

		fs.Destroy()
		os.Exit(0)
	}()

	err = fs.ConnectToFuse()
	if err != nil {
		logger.Error(err)
		if isChildProcess {
			fmt.Fprintln(os.Stderr, InterProcessCommunicationFinishError)
		}

		fs.Destroy()
		return err
	}

	if isChildProcess {
		fmt.Fprintln(os.Stdout, InterProcessCommunicationFinishSuccess)
		if len(config.LogPath) == 0 {
			// stderr is not a local file, so is closed by parent
			var nilWriter NilWriter
			log.SetOutput(&nilWriter)
		}
	}

	err = fs.StartFuse()
	if err != nil {
		logger.WithError(err).Error("Could not start FUSE")
		fs.Destroy()
		return err
	}

	// returns if mount fails, or stopped.
	fs.Destroy()
	return nil
}
