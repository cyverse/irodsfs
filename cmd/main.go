package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"

	cmd_commons "github.com/cyverse/irodsfs/cmd/commons"
	"github.com/cyverse/irodsfs/commons"
	"github.com/cyverse/irodsfs/irodsfs"
	"github.com/cyverse/irodsfs/utils"
	"github.com/spf13/cobra"

	"github.com/pkg/profile"
	log "github.com/sirupsen/logrus"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "irodsfs [iRODS URL] mount_point",
	Short: "Run iRODS FUSE Lite",
	Long:  "Run iRODS FUSE Lite that mounts iRODS collections on the directory hierarchy.",
	RunE:  processCommand,
}

func Execute() error {
	return rootCmd.Execute()
}

func processCommand(command *cobra.Command, args []string) error {
	// check if this is subprocess running in the background
	isChildProc := false
	childProcessArgument := fmt.Sprintf("-%s", cmd_commons.ChildProcessArgument)

	for _, arg := range os.Args {
		if len(arg) >= len(childProcessArgument) {
			if arg == childProcessArgument || arg[1:] == childProcessArgument {
				// background
				isChildProc = true
				break
			}
		}
	}

	if isChildProc {
		// child process
		childMain(command, args)
	} else {
		// parent process
		parentMain(command, args)
	}

	return nil
}

func main() {
	log.SetFormatter(&log.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05.000000",
		FullTimestamp:   true,
	})

	log.SetLevel(log.InfoLevel)

	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "main",
	})

	// attach common flags
	cmd_commons.SetCommonFlags(rootCmd)

	err := Execute()
	if err != nil {
		logger.Fatal(err)
		os.Exit(1)
	}
}

// parentMain handles command-line parameters and run parent process
func parentMain(command *cobra.Command, args []string) {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "parentMain",
	})

	config, logWriter, cont, err := cmd_commons.ProcessCommonFlags(command, args)
	if logWriter != nil {
		defer logWriter.Close()
	}

	if err != nil {
		logger.Errorf("%+v", err)
		os.Exit(1)
	}

	if !cont {
		os.Exit(0)
	}

	// check fuse
	fuseCheckResult := utils.CheckFuse()
	switch fuseCheckResult {
	case utils.CheckFUSEStatusFound:
		// okay
		logger.Info("Found FUSE Device. Starting iRODS FUSE Lite.")
	case utils.CheckFUSEStatusUnknown:
		// try to go
		logger.Info("It is not sure whether FUSE is running. Starting iRODS FUSE Lite, anyway.")
	case utils.CheckFUSEStatusNotFound:
		logger.Error("FUSE is not running. Terminating iRODS FUSE Lite.")
		os.Exit(1)
	case utils.CheckFUSEStatusCannotRun:
		logger.Error("FUSE is not supported. Terminating iRODS FUSE Lite.")
		os.Exit(1)
	}

	if !config.Foreground {
		// background
		childStdin, childStdout, err := cmd_commons.RunChildProcess(os.Args[0])
		if err != nil {
			logger.WithError(err).Error("failed to run iRODS FUSE Lite child process")
			os.Exit(1)
		}

		err = cmd_commons.ParentProcessSendConfigViaSTDIN(config, childStdin, childStdout)
		if err != nil {
			logger.WithError(err).Error("failed to send configuration to iRODS FUSE Lite child process")
			os.Exit(1)
		}
	} else {
		// run foreground
		err = run(config, false)
		if err != nil {
			logger.WithError(err).Error("failed to run iRODS FUSE Lite")
			os.Exit(1)
		}
	}
}

// childMain runs child process
func childMain(command *cobra.Command, args []string) {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "childMain",
	})

	logger.Info("Start child process")

	// read from stdin
	config, logWriter, err := cmd_commons.ChildProcessReadConfigViaSTDIN()
	if logWriter != nil {
		defer logWriter.Close()
	}

	if err != nil {
		logger.WithError(err).Error("failed to communicate to parent process")
		cmd_commons.ReportChildProcessError()
		os.Exit(1)
	}

	config.ChildProcess = true

	logger.Info("Run child process")

	// background
	err = run(config, true)
	if err != nil {
		logger.WithError(err).Error("failed to run iRODS FUSE Lite")
		os.Exit(1)
	}

	if logWriter != nil {
		logWriter.Close()
	}
}

// run runs iRODS FUSE Lite
func run(config *commons.Config, isChildProcess bool) error {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "run",
	})

	if config.Debug {
		log.SetLevel(log.DebugLevel)
	}

	versionInfo := commons.GetVersion()
	logger.Infof("iRODS FUSE Lite version - %s, commit - %s", versionInfo.ClientVersion, versionInfo.GitCommit)

	err := config.Validate()
	if err != nil {
		logger.WithError(err).Error("invalid configuration")
		return err
	}

	// profile
	if config.Profile && config.ProfileServicePort > 0 {
		go func() {
			profileServiceAddr := fmt.Sprintf(":%d", config.ProfileServicePort)

			logger.Infof("Starting profile service at %s", profileServiceAddr)
			http.ListenAndServe(profileServiceAddr, nil)
		}()

		prof := profile.Start(profile.MemProfile)
		defer prof.Stop()
	}

	// run the filesystem
	fs, err := irodsfs.NewFileSystem(config)
	if err != nil {
		logger.WithError(err).Error("failed to create the filesystem")
		if isChildProcess {
			cmd_commons.ReportChildProcessError()
		}
		return err
	}

	err = fs.Start()
	if err != nil {
		logger.WithError(err).Error("failed to start the filesystem")
		if isChildProcess {
			cmd_commons.ReportChildProcessError()
		}

		fs.Release()
		return err
	}

	if isChildProcess {
		cmd_commons.ReportChildProcessStartSuccessfully()
		if len(config.GetLogFilePath()) == 0 {
			cmd_commons.SetNilLogWriter()
		}
	}

	defer func() {
		logger.Info("exiting")
		fs.Stop()
		fs.Release()

		os.Exit(0)
	}()

	// handle ctrl + C
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	go func() {
		<-signalChannel
		logger.Info("received intrrupt")
		fs.Stop() // this unmounts fuse
		logger.Info("stopped the filesystem, unmounting FUSE")
	}()

	// wait
	fs.Wait()

	return nil
}
