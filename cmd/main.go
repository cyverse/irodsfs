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
	"golang.org/x/xerrors"

	"github.com/pkg/profile"
	log "github.com/sirupsen/logrus"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:           "irodsfs [iRODS URL] mount_point",
	Short:         "Run iRODS FUSE Lite",
	Long:          "Run iRODS FUSE Lite that mounts iRODS collections on the directory hierarchy.",
	RunE:          processCommand,
	SilenceUsage:  true,
	SilenceErrors: true,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd:   true,
		DisableNoDescFlag:   true,
		DisableDescriptions: true,
		HiddenDefaultCmd:    true,
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func processCommand(command *cobra.Command, args []string) error {
	// check if this is subprocess running in the background
	if cmd_commons.IsChildProcess(command) {
		// child process
		childMain()
		return nil
	} else if cmd_commons.IsWatchdogProcess(command) {
		// watchdog process
		watchdogMain()
		return nil
	}

	// parent process
	return parentMain(command, args)
}

func main() {
	commons.InitTerminalOutput()

	log.SetFormatter(&log.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05.000000",
		FullTimestamp:   true,
	})

	log.SetLevel(log.InfoLevel)
	log.SetOutput(commons.GetTerminalWriter())

	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "main",
	})

	// attach common flags
	cmd_commons.SetCommonFlags(rootCmd)

	err := Execute()
	if err != nil {
		logger.Errorf("%+v", err)
		commons.PrintErrorf("%+v\n", err)
		os.Exit(1)
	}
}

// parentMain handles command-line parameters and run parent process
func parentMain(command *cobra.Command, args []string) error {
	config, logWriter, cont, err := cmd_commons.ProcessCommonFlags(command, args)
	if logWriter != nil {
		defer logWriter.Close()
	}

	if err != nil {
		return err
	}

	if !cont {
		return nil
	}

	// check fuse
	err = utils.EnsureFuse()
	if err != nil {
		return err
	}

	if !config.Foreground {
		// background
		childStdin, childStdout, err := cmd_commons.RunChildProcess(os.Args[0])
		if err != nil {
			return xerrors.Errorf("failed to run iRODS FUSE Lite child process: %w", err)
		}

		err = cmd_commons.ParentProcessSendConfigViaSTDIN(config, childStdin, childStdout)
		if err != nil {
			return xerrors.Errorf("failed to send configuration to iRODS FUSE Lite child process: %w", err)
		}
	} else {
		// run foreground
		err = run(config, false)
		if err != nil {
			return xerrors.Errorf("failed to run iRODS FUSE Lite: %w", err)
		}
	}

	return nil
}

// childMain runs child process
func childMain() {
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
		commErr := xerrors.Errorf("failed to communicate to parent process: %w", err)
		logger.Errorf("%+v", commErr)
		cmd_commons.ReportChildProcessError()
		os.Exit(1)
	}

	config.ChildProcess = true

	logger.Info("Run child process")

	// background
	err = run(config, true)
	if err != nil {
		runErr := xerrors.Errorf("failed to run iRODS FUSE Lite: %w", err)
		logger.Errorf("%+v", runErr)
		os.Exit(1)
	}

	if logWriter != nil {
		logWriter.Close()
		logWriter = nil
	}
}

// watchdogMain runs watchdog process
func watchdogMain() {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "watchdogMain",
	})

	logger.Info("Start watchdog process")

	// read from stdin
	config, logWriter, err := cmd_commons.WatchdogProcessReadConfigViaSTDIN()
	if logWriter != nil {
		defer logWriter.Close()
	}

	if err != nil {
		commErr := xerrors.Errorf("failed to communicate to parent process: %w", err)
		logger.Errorf("%+v", commErr)
		cmd_commons.ReportChildProcessError()
		os.Exit(1)
	}

	config.WatchdogProcess = true

	logger.Info("Run watchdog")

	cmd_commons.ReportChildProcessStartSuccessfully()
	if len(config.GetLogFilePath()) == 0 {
		cmd_commons.SetNilLogWriter()
	}

	cmd_commons.WatchParentProcess(config.WatchPID, config.MountPath)

	if logWriter != nil {
		logWriter.Close()
		logWriter = nil
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
	logger.Infof("iRODS FUSE Lite version %q, commit %q", versionInfo.ClientVersion, versionInfo.GitCommit)

	err := config.Validate()
	if err != nil {
		configErr := xerrors.Errorf("invalid configuration: %w", err)
		logger.Errorf("%+v", configErr)

		if isChildProcess {
			cmd_commons.ReportChildProcessError()
		}
		return err
	}

	// profile
	if config.Profile && config.ProfileServicePort > 0 {
		go func() {
			profileServiceAddr := fmt.Sprintf(":%d", config.ProfileServicePort)

			logger.Infof("Starting profile service at %q", profileServiceAddr)
			http.ListenAndServe(profileServiceAddr, nil)
		}()

		prof := profile.Start(profile.MemProfile)
		defer prof.Stop()
	}

	// run the filesystem
	fs, err := irodsfs.NewFileSystem(config)
	if err != nil {
		fsErr := xerrors.Errorf("failed to create the filesystem: %w", err)
		logger.Errorf("%+v", fsErr)

		if isChildProcess {
			cmd_commons.ReportChildProcessError()
		}
		return fsErr
	}

	// iRODS connection must be established correctly by here
	// any network errors from here will be recoverable
	err = fs.Start()
	if err != nil {
		fsErr := xerrors.Errorf("failed to start the filesystem: %w", err)
		logger.Errorf("%+v", fsErr)
		if isChildProcess {
			cmd_commons.ReportChildProcessError()
		}

		fs.Release()
		return fsErr
	}

	if isChildProcess {
		cmd_commons.ReportChildProcessStartSuccessfully()
		if len(config.GetLogFilePath()) == 0 {
			cmd_commons.SetNilLogWriter()
		}
	}

	defer func() {
		logger.Info("exiting")
		fs.Stop(true)
		fs.Release()

		os.Exit(0)
	}()

	// handle ctrl + C
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	go func() {
		<-signalChannel
		logger.Info("received intrrupt")
		fs.Stop(false) // this unmounts fuse
		logger.Info("stopped the filesystem, unmounting FUSE")
	}()

	// watch
	watchdogStdin, watchdogStdout, err := cmd_commons.RunWatchdogProcess(os.Args[0])
	if err != nil {
		return xerrors.Errorf("failed to run watchdog process: %w", err)
	}

	config.WatchPID = os.Getpid()
	err = cmd_commons.WatchtargetProcessSendConfigViaSTDIN(config, watchdogStdin, watchdogStdout)
	if err != nil {
		return xerrors.Errorf("failed to send configuration to iRODS FUSE Lite watchdog process: %w", err)
	}

	// wait
	fs.Wait()

	return nil
}
