package commons

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/cyverse/irodsfs/commons"
	"github.com/cyverse/irodsfs/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

func RunWatchdogProcess(serverExec string) (io.WriteCloser, io.ReadCloser, error) {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "RunWatchdogProcess",
	})

	// run watchdog process in background and pass parameters via stdin PIPE
	// receives result from the watchdog process
	logger.Info("Running the watchdog process in the background mode")
	cmd := exec.Command(serverExec, "--watchdog_process")
	watchdogStdin, err := cmd.StdinPipe()
	if err != nil {
		pipeErr := xerrors.Errorf("failed to get the watchdog process's STDIN: %w", err)
		logger.Errorf("%+v", pipeErr)
		return nil, nil, pipeErr
	}

	watchdogStdout, err := cmd.StdoutPipe()
	if err != nil {
		pipeErr := xerrors.Errorf("failed to get the watchdog process's STDOUT: %w", err)
		logger.Errorf("%+v", pipeErr)
		return nil, nil, pipeErr
	}

	// start
	err = cmd.Start()
	if err != nil {
		cmdErr := xerrors.Errorf("failed to start the watchdog process: %w", err)
		logger.Errorf("%+v", cmdErr)
		return nil, nil, cmdErr
	}

	logger.Infof("Watchdog process id = %d", cmd.Process.Pid)
	return watchdogStdin, watchdogStdout, nil
}

func WatchtargetProcessSendConfigViaSTDIN(config *commons.Config, stdin io.WriteCloser, stdout io.ReadCloser) error {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "WatchtargetProcessSendConfigViaSTDIN",
	})

	logger.Info("Sending configuration via STDIN")
	configBytes, err := yaml.Marshal(config)
	if err != nil {
		yamlErr := xerrors.Errorf("failed to marshal configuration to yaml: %w", err)
		logger.Errorf("%+v", yamlErr)
		return yamlErr
	}

	// send it to watchdog
	_, err = stdin.Write(configBytes)
	if err != nil {
		writeErr := xerrors.Errorf("failed to send via STDIN: %w", err)
		logger.Errorf("%+v", writeErr)
		return writeErr
	}

	stdin.Close()

	logger.Info("Successfully sent configuration to STDIN")

	// receive output from watchdog
	watchdogProcessFailed := false
	watchdogOutputScanner := bufio.NewScanner(stdout)
	for {
		if watchdogOutputScanner.Scan() {
			errMsg := strings.TrimSpace(watchdogOutputScanner.Text())
			if errMsg == InterProcessCommunicationFinishSuccess {
				logger.Info("Successfully started watchdog process")
				break
			} else if errMsg == InterProcessCommunicationFinishError {
				logger.Error("failed to start watchdog process")
				watchdogProcessFailed = true
				break
			} else {
				logger.Info(errMsg)
			}
		} else {
			// check err
			if watchdogOutputScanner.Err() != nil {
				logger.Error(watchdogOutputScanner.Err().Error())
				watchdogProcessFailed = true
				break
			}
		}
	}

	if watchdogProcessFailed {
		return xerrors.Errorf("failed to start watchdog process")
	}

	return nil
}

func WatchdogProcessReadConfigViaSTDIN() (*commons.Config, io.WriteCloser, error) {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "WatchdogProcessReadConfigViaSTDIN",
	})

	// read from stdin
	logger.Info("Check STDIN to communicate to other process")
	_, err := os.Stdin.Stat()
	if err != nil {
		statErr := xerrors.Errorf("failed to read from STDIN: %w", err)
		logger.Errorf("%+v", statErr)
		return nil, nil, statErr
	}

	logger.Info("Reading configuration from STDIN")
	configBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		readErr := xerrors.Errorf("failed to read configuration: %w", err)
		logger.Errorf("%+v", readErr)
		return nil, nil, readErr
	}
	logger.Info("Successfully read configuration from STDIN")

	config, err := commons.NewConfigFromYAML(nil, configBytes)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, nil, err
	}

	if config.Debug {
		log.SetLevel(log.DebugLevel)
	}

	// permission check fails during validation, as fuse is overwriting the permission
	//err = config.Validate()
	//if err != nil {
	//	logger.Errorf("%+v", err)
	//	return nil, nil, err
	//}

	err = config.MakeLogDir()
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, nil, err
	}

	// output to log file
	logFilePath := config.GetLogFilePath()
	if len(logFilePath) > 0 && logFilePath != "-" {
		logWriter, watchdogLogFilePath := getLogWriterForWatchdogProcess(logFilePath)
		log.SetOutput(logWriter)

		logger.Infof("Logging to %q", watchdogLogFilePath)
		return config, logWriter, nil
	} else {
		var nilWriter NilWriter
		log.SetOutput(&nilWriter)
		return config, &nilWriter, nil
	}
}

func WatchParentProcess(ppid int, mountPath string) {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "WatchParentProcess",
	})

	// for every 1 sec, check parent process
	tickerCheck := time.NewTicker(1 * time.Second)
	defer tickerCheck.Stop()

	for {
		<-tickerCheck.C

		if !checkParentProcess(ppid) {
			// parent process is already dead
			if checkMount(mountPath) {
				// unmount
				err := utils.UnmountFuse(mountPath)
				if err != nil {
					logger.Errorf("failed to unmount %q: %v", mountPath, err)
				}

				// exit
				logger.Infof("unmounted %q", mountPath)
			}

			logger.Info("exiting check loop")
			break
		}
	}
}

func checkParentProcess(ppid int) bool {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "checkParentProcess",
	})

	// check parent process
	if os.Getppid() != ppid {
		logger.Info("Parent process is already dead")
		return false
	}

	return true
}

func checkMount(mountPath string) bool {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "checkMount",
	})

	f, err := os.Open("/proc/mounts")
	if err != nil {
		logger.Errorf("failed to open '/proc/mounts': %v", err)
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "irodsfs" {
			if path.Clean(fields[1]) == path.Clean(mountPath) {
				// same one
				return true
			}
		}
	}

	logger.Infof("Mount point %q is not mounted", mountPath)
	return false
}
