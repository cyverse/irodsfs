package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"

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

		err, shutdownFn := run(&config)
		if err != nil {
			runErr := errors.Errorf("failed to run iRODS FUSE: %w", err)
			logger.Error(runErr)

			ready(runErr)
			os.Exit(1)
		} else {
			ready(nil)
		}

		// wait
		waitForCtrlC()

		if shutdownFn != nil {
			shutdownFn()
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

		err, shutdownFn := run(config)
		if err != nil {
			runErr := errors.Wrapf(err, "failed to run iRODS FUSE")
			logger.Error(runErr)
		}

		// wait
		waitForCtrlC()

		if shutdownFn != nil {
			shutdownFn()
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

	// must be called before cobra parses os.Args so --__daemon__ is stripped
	daemon = godaemonizer.New()

	// attach common flags
	cmd_commons.SetCommonFlags(rootCmd)

	err := Execute()
	if err != nil {
		logger.Fatal(err)
		os.Exit(1)
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

	// make work dirs required
	err := config.MakeWorkDirs()
	if err != nil {
		mkdirErr := errors.Wrapf(err, "make work dir error")
		logger.Error(mkdirErr)
		return err, nil
	}

	err = config.Validate()
	if err != nil {
		configErr := errors.Wrapf(err, "invalid configuration")
		logger.Error(configErr)
		return err, nil
	}

	// run the filesystem
	fs, err := irodsfs.NewFileSystem(config)
	if err != nil {
		fsErr := errors.Wrapf(err, "failed to create the filesystem")
		logger.Error(fsErr)
		return fsErr, nil
	}

	// iRODS connection must be established correctly by here
	// any network errors from here will be recoverable
	err = fs.Mount()
	if err != nil {
		fsErr := errors.Wrapf(err, "failed to start the filesystem")
		logger.Error(fsErr)
		fs.Release()
		return fsErr, nil
	}

	shutdown := func() {
		fs.Unmount()
		fs.Release()

		os.Exit(0)
	}

	return nil, shutdown
}

func waitForCtrlC() {
	var endWaiter sync.WaitGroup

	endWaiter.Add(1)
	signalChannel := make(chan os.Signal, 1)

	signal.Notify(signalChannel, os.Interrupt)

	go func() {
		<-signalChannel
		endWaiter.Done()
	}()

	endWaiter.Wait()
}
