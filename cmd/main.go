package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cockroachdb/errors"
	godaemonizer "github.com/cyverse/go-daemonizer"
	irodsfs_common_util "github.com/cyverse/irodsfs-common/util"
	cmd_commons "github.com/cyverse/irodsfs/cmd/commons"
	"github.com/cyverse/irodsfs/commons"
	"github.com/cyverse/irodsfs/irodsfs"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:           "irodsfs [args..] [mount_point]",
	Short:         "Run iRODS FUSE",
	Long:          "Run iRODS FUSE that mounts iRODS collections on the directory hierarchy.",
	RunE:          processCommand,
	SilenceUsage:  true,
	SilenceErrors: true,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd:   true,
		DisableNoDescFlag:   true,
		DisableDescriptions: true,
		HiddenDefaultCmd:    true,
	},
	Args: cobra.RangeArgs(0, 1),
}

var daemon *godaemonizer.Daemon

func Execute() error {
	return rootCmd.Execute()
}

func processCommand(command *cobra.Command, args []string) error {
	logger := log.WithFields(log.Fields{})

	// foreground app
	config, cont, err := cmd_commons.ProcessCommonFlags(command, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to process flags: %v\n", err)
		os.Exit(1)
	}

	if !cont {
		os.Exit(0)
	}

	if !config.Foreground {
		fmt.Println("run as daemon")

		if !daemon.IsDaemon() {
			logWriter, err := config.GetLogWriter(true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to get log writer: %v\n", err)
				os.Exit(1)
			}

			if logWriter != nil {
				defer logWriter.Close()
			}

			log.SetOutput(logWriter)

			err = daemon.Daemonize(context.Background(), config, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to daemonize: %v\n", err)
				logger.WithError(err).Fatal("failed to daemonize")
				os.Exit(1)
			}

			fmt.Println("daemon started successfully")
			logger.Info("daemon started successfully")
			return nil
		}

		// daemon process
		logWriter, err := config.GetLogWriter(false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get log writer: %v\n", err)
			os.Exit(1)
		}

		if logWriter != nil {
			defer logWriter.Close()
		}

		log.SetOutput(logWriter)

		var config commons.Config
		ready, err := daemon.WaitForParent(&config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to receive params: %v\n", err)
			logger.WithError(err).Fatal("failed to receive params")
			os.Exit(1)
		}

		err = runManaged(&config, ready)
		if err != nil {
			runErr := errors.Errorf("failed to run iRODS FUSE: %w", err)
			logger.Error(runErr)
			return runErr
		}
	} else {
		// run foreground
		fmt.Println("run foreground")

		logWriter, err := config.GetLogWriter(true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get log writer: %v\n", err)
			os.Exit(1)
		}

		if logWriter != nil {
			defer logWriter.Close()
			log.SetOutput(logWriter)
		}

		err = runManaged(config, nil)
		if err != nil {
			runErr := errors.Wrapf(err, "failed to run iRODS FUSE")
			logger.Error(runErr)
			return runErr
		}
	}

	return nil
}

func main() {
	myFormatter := &irodsfs_common_util.StacktraceTextFormatter{
		TextFormatter: log.TextFormatter{
			TimestampFormat: "2006-01-02 15:04:05.000000",
			FullTimestamp:   true,
		},
	}

	log.SetFormatter(myFormatter)
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(true)

	logger := log.WithFields(log.Fields{})

	// go-daemonizer relaunches os.Args[0]. Use an absolute path so daemon
	// startup does not depend on the configured working directory.
	executable, err := os.Executable()
	if err != nil {
		logger.WithError(err).Fatal("failed to resolve executable path")
	}
	os.Args[0] = executable

	// must be called before cobra parses os.Args so --__daemon__ is stripped
	daemon = godaemonizer.New()

	// attach common flags
	cmd_commons.SetCommonFlags(rootCmd)

	err = Execute()
	if err != nil {
		logger.Fatal(err)
		os.Exit(1)
	}
}

func runManaged(config *commons.Config, ready func(error)) error {
	runErr, shutdownFn := run(config)
	if runErr != nil {
		reportReady(ready, runErr)
		return runErr
	}

	reportReady(ready, nil)
	waitForShutdown()

	if shutdownFn != nil {
		shutdownFn()
	}
	return nil
}

func reportReady(ready func(error), err error) {
	if ready != nil {
		ready(err)
	}
}

// run runs iRODS FUSE
func run(config *commons.Config) (error, func()) {
	logger := log.WithFields(log.Fields{})

	if config.Debug {
		log.SetLevel(log.DebugLevel)
	}

	versionInfo := commons.GetVersion()
	logger.Infof("iRODS FUSE version - %q, commit - %q", versionInfo.ClientVersion, versionInfo.GitCommit)

	if err := config.MakeWorkDirs(); err != nil {
		mkdirErr := errors.Wrapf(err, "make work dir error")
		logger.Error(mkdirErr)
		return err, nil
	}

	if err := config.Validate(); err != nil {
		configErr := errors.Wrapf(err, "invalid configuration")
		logger.Error(configErr)
		return err, nil
	}

	fs, err := irodsfs.NewFileSystem(config)
	if err != nil {
		fsErr := errors.Wrapf(err, "failed to create the filesystem")
		logger.Error(fsErr)
		return fsErr, nil
	}

	// iRODS connection must be established correctly by here
	// any network errors from here will be recoverable
	if err := fs.Mount(); err != nil {
		fsErr := errors.Wrapf(err, "failed to start the filesystem")
		logger.Error(fsErr)
		fs.Release()
		return fsErr, nil
	}

	shutdown := func() {
		fs.Unmount()
		fs.Release()
	}

	return nil, shutdown
}

func waitForShutdown() {
	signalChannel := make(chan os.Signal, 1)

	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalChannel)
	<-signalChannel
}
