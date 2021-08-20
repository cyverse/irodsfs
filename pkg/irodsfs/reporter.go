package irodsfs

import (
	"fmt"
	"time"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	monitor_client "github.com/cyverse/irodsfs-monitor/client"
	monitor_types "github.com/cyverse/irodsfs-monitor/types"
	log "github.com/sirupsen/logrus"
)

const (
	MaxTransferBlockLen       int = 50
	ReporterRequestTimeoutSec int = 5
)

// MonitoringReporter reports metrics to monitoring service
type MonitoringReporter struct {
	MonitorURL        string
	MonitoringClient  *monitor_client.APIClient
	Failed            bool
	InstanceID        string
	FileTransferMap   map[string]*monitor_types.ReportFileTransfer
	NextFileOffsetMap map[string]int64
	IgnoreError       bool
}

// NewMonitoringReporter creates a new monitoring reporter
func NewMonitoringReporter(monitorURL string, ignoreError bool) *MonitoringReporter {
	var monitoringClient *monitor_client.APIClient
	if len(monitorURL) > 0 {
		monitoringClient = monitor_client.NewAPIClient(monitorURL, time.Second*time.Duration(ReporterRequestTimeoutSec))
	}

	return &MonitoringReporter{
		MonitorURL:        monitorURL,
		Failed:            false,
		MonitoringClient:  monitoringClient,
		InstanceID:        "",
		FileTransferMap:   map[string]*monitor_types.ReportFileTransfer{},
		NextFileOffsetMap: map[string]int64{},
		IgnoreError:       ignoreError,
	}
}

// ReportNewInstance reports creation of a new iRODS FUSE Lite instance
func (reporter *MonitoringReporter) ReportNewInstance(fsConfig *Config) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "MonitoringReporter.ReportNewInstance",
	})

	if reporter.MonitoringClient != nil {
		instance := monitor_types.ReportInstance{
			Host:                     fsConfig.Host,
			Port:                     fsConfig.Port,
			Zone:                     fsConfig.Zone,
			ClientUser:               fsConfig.ClientUser,
			ProxyUser:                fsConfig.ProxyUser,
			AuthScheme:               fsConfig.AuthScheme,
			ReadAheadMax:             fsConfig.ReadAheadMax,
			OperationTimeout:         fsConfig.OperationTimeout.String(),
			ConnectionIdleTimeout:    fsConfig.ConnectionIdleTimeout.String(),
			ConnectionMax:            fsConfig.ConnectionMax,
			MetadataCacheTimeout:     fsConfig.MetadataCacheTimeout.String(),
			MetadataCacheCleanupTime: fsConfig.MetadataCacheCleanupTime.String(),
			FileBufferSizeMax:        fsConfig.FileBufferSizeMax,

			CreationTime: time.Now().UTC(),
		}

		if !reporter.Failed {
			instanceID, err := reporter.MonitoringClient.AddInstance(&instance)
			if err != nil {
				logger.WithError(err).Error("failed to report the instance to monitoring service")
				reporter.Failed = true

				if !reporter.IgnoreError {
					return err
				}
			}

			reporter.InstanceID = instanceID
		}
	}

	return nil
}

// ReportInstanceTermination reports termination of the iRODS FUSE Lite instance
func (reporter *MonitoringReporter) ReportInstanceTermination() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "MonitoringReporter.ReportInstanceTermination",
	})

	if !reporter.Failed {
		if reporter.MonitoringClient != nil {
			if len(reporter.InstanceID) > 0 {
				err := reporter.MonitoringClient.TerminateInstance(reporter.InstanceID)
				if err != nil {
					logger.WithError(err).Error("failed to report termination of the instance to monitoring service")
					reporter.Failed = true

					if !reporter.IgnoreError {
						return err
					}
				}
			}
		}
	}

	return nil
}

func (reporter *MonitoringReporter) makeFileTransferKey(path string, fileHandle *irodsfs_client.FileHandle) string {
	return fmt.Sprintf("%s:%p", path, fileHandle)
}

// ReportNewFileTransferStart reports a new file transfer start
func (reporter *MonitoringReporter) ReportNewFileTransferStart(path string, fileHandle *irodsfs_client.FileHandle, size int64) {
	if !reporter.Failed {
		if reporter.MonitoringClient != nil {
			if len(reporter.InstanceID) > 0 {
				transferReport := &monitor_types.ReportFileTransfer{
					InstanceID: reporter.InstanceID,

					FilePath:     path,
					FileSize:     size,
					FileOpenMode: string(fileHandle.OpenMode),

					TransferBlocks:     make([]monitor_types.FileBlock, 0, MaxTransferBlockLen),
					TransferSize:       0,
					LargestBlockSize:   0,
					SmallestBlockSize:  0,
					TransferBlockCount: 0,
					SequentialAccess:   true,

					FileOpenTime: time.Now().UTC(),
				}

				key := reporter.makeFileTransferKey(path, fileHandle)
				reporter.FileTransferMap[key] = transferReport
				reporter.NextFileOffsetMap[key] = 0
			}
		}
	}
}

// ReportFileTransferDone reports that the file transfer is done
func (reporter *MonitoringReporter) ReportFileTransferDone(path string, fileHandle *irodsfs_client.FileHandle) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "MonitoringReporter.ReportFileTransferDone",
	})

	if !reporter.Failed {
		if reporter.MonitoringClient != nil {
			key := reporter.makeFileTransferKey(path, fileHandle)
			if transfer, ok := reporter.FileTransferMap[key]; ok {
				transfer.FileCloseTime = time.Now().UTC()

				err := reporter.MonitoringClient.AddFileTransfer(transfer)
				if err != nil {
					logger.WithError(err).Error("failed to report file transfer to monitoring service")
					reporter.Failed = true

					if !reporter.IgnoreError {
						return err
					}
				}

				delete(reporter.FileTransferMap, key)
				delete(reporter.NextFileOffsetMap, key)
			}
		}
	}

	return nil
}

// ReportFileTransfer reports a new file transfer
func (reporter *MonitoringReporter) ReportFileTransfer(path string, fileHandle *irodsfs_client.FileHandle, offset int64, length int64) {
	if !reporter.Failed {
		if reporter.MonitoringClient != nil {
			key := reporter.makeFileTransferKey(path, fileHandle)
			if transfer, ok := reporter.FileTransferMap[key]; ok {
				block := monitor_types.FileBlock{
					Offset:     offset,
					Length:     length,
					AccessTime: time.Now().UTC(),
				}

				transfer.TransferSize += int64(length)
				transfer.TransferBlockCount++
				if transfer.LargestBlockSize < length {
					transfer.LargestBlockSize = length
				}

				if transfer.SmallestBlockSize == 0 {
					transfer.SmallestBlockSize = length
				} else if transfer.SmallestBlockSize > length {
					transfer.SmallestBlockSize = length
				}

				isSequential := false
				if nextOffset, ok2 := reporter.NextFileOffsetMap[key]; ok2 {
					if nextOffset == offset {
						// current block is the next one of previous transfer
						isSequential = true
					} else {
						// random access
						isSequential = false
					}
				}

				reporter.NextFileOffsetMap[key] = offset + length

				if !isSequential {
					transfer.SequentialAccess = false
				}

				if isSequential {
					reporter.addFileTransferSequential(transfer, block)
				} else {
					transfer.SequentialAccess = false
					reporter.addFileTransferRandom(transfer, block)
				}
			}
		}
	}
}

// addFileTransfer adds the file transfer to the list
func (reporter *MonitoringReporter) addFileTransferSequential(transfer *monitor_types.ReportFileTransfer, block monitor_types.FileBlock) {
	if len(transfer.TransferBlocks) < MaxTransferBlockLen {
		if len(transfer.TransferBlocks) == 0 {
			transfer.TransferBlocks = append(transfer.TransferBlocks, block)
			return
		} else {
			// merge to last
			lastBlock := transfer.TransferBlocks[len(transfer.TransferBlocks)-1]
			lastBlock.Length += block.Length

			transfer.TransferBlocks[len(transfer.TransferBlocks)-1] = lastBlock
			return
		}
	}
}

// addFileTransfer adds the file transfer to the list
func (reporter *MonitoringReporter) addFileTransferRandom(transfer *monitor_types.ReportFileTransfer, block monitor_types.FileBlock) {
	if len(transfer.TransferBlocks) < MaxTransferBlockLen {
		// add to last
		transfer.TransferBlocks = append(transfer.TransferBlocks, block)
	}
}
