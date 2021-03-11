package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"

	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	"github.com/cyverse/irodsfs/pkg/irodsfs"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

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

		cmd.Start()

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
		logger.Info("Successfully sent configuration data")

	} else {
		// foreground
		err = run(config)
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

	config, err := processArguments()
	if err != nil {
		logger.WithError(err).Error("Error occurred while processing arguments")
		logger.Fatal(err)
	}

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

	// read from stdin
	_, err := os.Stdin.Stat()
	if err != nil {
		logger.WithError(err).Error("Could not communicate to foreground process")
		logger.Fatal(err)
	}

	configBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		logger.WithError(err).Error("Could not read configuration")
		logger.Fatal(err)
	}

	config, err := irodsfs.NewConfigFromYAML(configBytes)
	if err != nil {
		logger.WithError(err).Error("Could not read configuration")
		logger.Fatal(err)
	}

	err = config.Validate()
	if err != nil {
		logger.WithError(err).Error("Argument validation error")
		logger.Fatal(err)
	}

	// background
	err = run(config)
	if err != nil {
		logger.WithError(err).Error("Could not run irodsfs")
		logger.Fatal(err)
	}
}

func run(config *irodsfs.Config) error {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "run",
	})

	fuseConn, err := fuse.Mount(config.MountPath, irodsfs.GetFuseMountOptions(config)...)
	if err != nil {
		logger.WithError(err).Error("Could not connect to FUSE")
		return err
	}
	defer fuseConn.Close()

	fuseServer := fusefs.New(fuseConn, nil)
	fs, err := irodsfs.NewFileSystem(config, fuseServer)
	if err != nil {
		logger.WithError(err).Error("Could not create filesystem")
		return err
	}

	if err := fuseServer.Serve(fs); err != nil {
		logger.WithError(err).Error("Could not start FUSE server")
		return err
	}
	return nil
}
