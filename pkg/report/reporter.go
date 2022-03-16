package report

import (
	"fmt"
	"sync"
	"time"

	monitor_client "github.com/cyverse/irodsfs-monitor/client"
	monitor_types "github.com/cyverse/irodsfs-monitor/types"
	"github.com/cyverse/irodsfs/pkg/commons"
	"github.com/cyverse/irodsfs/pkg/irodsapi"
	log "github.com/sirupsen/logrus"
)

const (
	// MaxTransferBlockLen defines how many transfer blocks we will log
	MaxTransferBlockLen int = 50
	// ReporterRequestTimeoutSec sets request timeout
	ReporterRequestTimeoutSec int = 5
)

// MonitoringReporter reports metrics to monitoring service
type MonitoringReporter struct {
	monitorURL        string
	client            *monitor_client.APIClient
	failed            bool
	instanceID        string
	fileTransferMap   map[string]*monitor_types.ReportFileTransfer
	nextFileOffsetMap map[string]int64
	mutex             sync.Mutex // lock for FileTransferMap and NextFileOffsetMap
	ignoreError       bool
}

// NewMonitoringReporter creates a new monitoring reporter
func NewMonitoringReporter(monitorURL string, ignoreError bool) *MonitoringReporter {
	var monitoringClient *monitor_client.APIClient
	if len(monitorURL) > 0 {
		monitoringClient = monitor_client.NewAPIClient(monitorURL, time.Second*time.Duration(ReporterRequestTimeoutSec))
	}

	return &MonitoringReporter{
		monitorURL:        monitorURL,
		failed:            false,
		client:            monitoringClient,
		instanceID:        "",
		fileTransferMap:   map[string]*monitor_types.ReportFileTransfer{},
		nextFileOffsetMap: map[string]int64{},
		mutex:             sync.Mutex{},
		ignoreError:       ignoreError,
	}
}

// ReportNewInstance reports creation of a new iRODS FUSE Lite instance
func (reporter *MonitoringReporter) ReportNewInstance(fsConfig *commons.Config) error {
	logger := log.WithFields(log.Fields{
		"package":  "report",
		"struct":   "MonitoringReporter",
		"function": "ReportNewInstance",
	})

	if reporter.client != nil {
		instance := monitor_types.ReportInstance{
			InstanceID: fsConfig.InstanceID,

			Host:                     fsConfig.Host,
			Port:                     fsConfig.Port,
			Zone:                     fsConfig.Zone,
			ClientUser:               fsConfig.ClientUser,
			ProxyUser:                fsConfig.ProxyUser,
			AuthScheme:               fsConfig.AuthScheme,
			ReadAheadMax:             fsConfig.ReadAheadMax,
			OperationTimeout:         time.Duration(fsConfig.OperationTimeout).String(),
			ConnectionIdleTimeout:    time.Duration(fsConfig.ConnectionIdleTimeout).String(),
			ConnectionMax:            fsConfig.ConnectionMax,
			MetadataCacheTimeout:     time.Duration(fsConfig.MetadataCacheTimeout).String(),
			MetadataCacheCleanupTime: time.Duration(fsConfig.MetadataCacheCleanupTime).String(),
			BufferSizeMax:            fsConfig.BufferSizeMax,

			PoolHost: fsConfig.PoolHost,
			PoolPort: fsConfig.PoolPort,

			CreationTime: time.Now().UTC(),
		}

		if !reporter.failed {
			instanceID, err := reporter.client.AddInstance(&instance)
			if err != nil {
				logger.WithError(err).Error("failed to report the instance to monitoring service")
				reporter.failed = true

				if !reporter.ignoreError {
					return err
				}
			}

			reporter.instanceID = instanceID
		}
	}

	return nil
}

// ReportInstanceTermination reports termination of the iRODS FUSE Lite instance
func (reporter *MonitoringReporter) ReportInstanceTermination() error {
	logger := log.WithFields(log.Fields{
		"package":  "report",
		"struct":   "MonitoringReporter",
		"function": "ReportInstanceTermination",
	})

	if !reporter.failed {
		if reporter.client != nil {
			if len(reporter.instanceID) > 0 {
				err := reporter.client.TerminateInstance(reporter.instanceID)
				if err != nil {
					logger.WithError(err).Error("failed to report termination of the instance to monitoring service")
					reporter.failed = true

					if !reporter.ignoreError {
						return err
					}
				}
			}
		}
	}

	return nil
}

func (reporter *MonitoringReporter) makeFileTransferKey(path string, fileHandle irodsapi.IRODSFileHandle) string {
	return fmt.Sprintf("%s:%s", path, fileHandle.GetID())
}

// ReportNewFileTransferStart reports a new file transfer start
func (reporter *MonitoringReporter) ReportNewFileTransferStart(path string, fileHandle irodsapi.IRODSFileHandle, size int64) {
	if !reporter.failed {
		if reporter.client != nil {
			if len(reporter.instanceID) > 0 {
				transferReport := &monitor_types.ReportFileTransfer{
					InstanceID: reporter.instanceID,

					FilePath:     path,
					FileSize:     size,
					FileOpenMode: string(fileHandle.GetOpenMode()),

					TransferBlocks:     make([]monitor_types.FileBlock, 0, MaxTransferBlockLen),
					TransferSize:       0,
					LargestBlockSize:   0,
					SmallestBlockSize:  0,
					TransferBlockCount: 0,
					SequentialAccess:   true,

					FileOpenTime: time.Now().UTC(),
				}

				key := reporter.makeFileTransferKey(path, fileHandle)

				reporter.mutex.Lock()
				defer reporter.mutex.Unlock()

				reporter.fileTransferMap[key] = transferReport
				reporter.nextFileOffsetMap[key] = 0

			}
		}
	}
}

// ReportFileTransferDone reports that the file transfer is done
func (reporter *MonitoringReporter) ReportFileTransferDone(path string, fileHandle irodsapi.IRODSFileHandle) error {
	logger := log.WithFields(log.Fields{
		"package":  "report",
		"struct":   "MonitoringReporter",
		"function": "ReportFileTransferDone",
	})

	if !reporter.failed {
		if reporter.client != nil {
			key := reporter.makeFileTransferKey(path, fileHandle)

			reporter.mutex.Lock()
			defer reporter.mutex.Unlock()

			if transfer, ok := reporter.fileTransferMap[key]; ok {
				transfer.FileCloseTime = time.Now().UTC()

				err := reporter.client.AddFileTransfer(transfer)
				if err != nil {
					logger.WithError(err).Error("failed to report file transfer to monitoring service")
					reporter.failed = true

					if !reporter.ignoreError {
						return err
					}
				}

				delete(reporter.fileTransferMap, key)
				delete(reporter.nextFileOffsetMap, key)
			}
		}
	}

	return nil
}

// ReportFileTransfer reports a new file transfer
func (reporter *MonitoringReporter) ReportFileTransfer(path string, fileHandle irodsapi.IRODSFileHandle, offset int64, length int64) {
	if !reporter.failed {
		if reporter.client != nil {
			key := reporter.makeFileTransferKey(path, fileHandle)

			reporter.mutex.Lock()
			defer reporter.mutex.Unlock()

			if transfer, ok := reporter.fileTransferMap[key]; ok {
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

				strictSequential := false
				mostlySequential := false
				if nextOffset, ok2 := reporter.nextFileOffsetMap[key]; ok2 {
					strictSequential, mostlySequential = reporter.checkSequentialTransfer(nextOffset, offset, length)
				}

				reporter.nextFileOffsetMap[key] = offset + length

				if !mostlySequential {
					transfer.SequentialAccess = false
				}

				if len(transfer.TransferBlocks) < MaxTransferBlockLen {
					if len(transfer.TransferBlocks) == 0 {
						transfer.TransferBlocks = append(transfer.TransferBlocks, block)
					} else {
						if strictSequential {
							// merge to last
							lastBlock := transfer.TransferBlocks[len(transfer.TransferBlocks)-1]
							lastBlock.Length += block.Length

							transfer.TransferBlocks[len(transfer.TransferBlocks)-1] = lastBlock
						} else {
							transfer.TransferBlocks = append(transfer.TransferBlocks, block)
						}
					}
				}
			}
		}
	}
}

// checkSequentialTransfer determines if the given file transfer is sequential transfer or not
// first return val: true if this is strictly sequential
// second return val: true if this is generally sequential
func (reporter *MonitoringReporter) checkSequentialTransfer(expectedOffset int64, transferOffset int64, transferLength int64) (bool, bool) {
	// 1 => 2 => 3 block order
	if expectedOffset == transferOffset {
		return true, true
	}

	// concurrent file transfer may make serial file access slightly unordered.
	// allow 3 => 1 => 2 block transfer order
	offsetDelta := expectedOffset - transferOffset
	if offsetDelta < 0 {
		offsetDelta *= -1
	}

	if offsetDelta <= transferLength*2 {
		return false, true
	}

	return false, false
}
