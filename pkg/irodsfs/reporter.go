package irodsfs

import (
	"time"

	monitor_client "github.com/cyverse/irodsfs-monitor/client"
	monitor_types "github.com/cyverse/irodsfs-monitor/types"
	log "github.com/sirupsen/logrus"
)

const (
	MaxTransferBlockLen int = 100
)

// MonitoringReporter reports metrics to monitoring service
type MonitoringReporter struct {
	MonitorURL        string
	MonitoringClient  *monitor_client.APIClient
	InstanceID        string
	FileTransferMap   map[string]*monitor_types.ReportFileTransfer
	NextFileOffsetMap map[string]int64
}

// NewMonitoringReporter creates a new monitoring reporter
func NewMonitoringReporter(monitorURL string) *MonitoringReporter {
	var monitoringClient *monitor_client.APIClient
	if len(monitorURL) > 0 {
		monitoringClient = monitor_client.NewAPIClient(monitorURL)
	}

	return &MonitoringReporter{
		MonitorURL:        monitorURL,
		MonitoringClient:  monitoringClient,
		InstanceID:        "",
		FileTransferMap:   map[string]*monitor_types.ReportFileTransfer{},
		NextFileOffsetMap: map[string]int64{},
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

		instanceID, err := reporter.MonitoringClient.AddInstance(&instance)
		if err != nil {
			logger.WithError(err).Error("Could not report the instance to monitoring service")
			return err
		}

		reporter.InstanceID = instanceID
	}

	return nil
}

// ReportInstanceTermination reports termination of the iRODS FUSE Lite instance
func (reporter *MonitoringReporter) ReportInstanceTermination() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "MonitoringReporter.ReportInstanceTermination",
	})

	if reporter.MonitoringClient != nil {
		if len(reporter.InstanceID) > 0 {
			err := reporter.MonitoringClient.TerminateInstance(reporter.InstanceID)
			if err != nil {
				logger.WithError(err).Error("Could not report termination of the instance to monitoring service")
				return err
			}
		}
	}

	return nil
}

// ReportNewFileTransferStart reports a new file transfer start
func (reporter *MonitoringReporter) ReportNewFileTransferStart(path string, size int64) {
	if reporter.MonitoringClient != nil {
		if len(reporter.InstanceID) > 0 {
			transferReport := &monitor_types.ReportFileTransfer{
				InstanceID: reporter.InstanceID,

				FilePath: path,
				FileSize: size,

				TransferBlocks:     make([]monitor_types.FileBlock, 0, MaxTransferBlockLen),
				TransferSize:       0,
				LargestBlockSize:   0,
				SmallestBlockSize:  0,
				TransferBlockCount: 0,
				SequentialAccess:   true,

				FileOpenTime: time.Now().UTC(),
			}

			reporter.FileTransferMap[path] = transferReport
			reporter.NextFileOffsetMap[path] = 0
		}
	}
}

// ReportFileTransferDone reports that the file transfer is done
func (reporter *MonitoringReporter) ReportFileTransferDone(path string) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "MonitoringReporter.ReportFileTransferDone",
	})

	if reporter.MonitoringClient != nil {
		if transfer, ok := reporter.FileTransferMap[path]; ok {
			transfer.FileCloseTime = time.Now().UTC()

			err := reporter.MonitoringClient.AddFileTransfer(transfer)
			if err != nil {
				logger.WithError(err).Error("Could not report file transfer to monitoring service")
				return err
			}

			delete(reporter.FileTransferMap, path)
			delete(reporter.NextFileOffsetMap, path)
		}
	}

	return nil
}

// ReportFileTransfer reports a new file transfer
func (reporter *MonitoringReporter) ReportFileTransfer(path string, offset int64, length int64) {
	if reporter.MonitoringClient != nil {
		if transfer, ok := reporter.FileTransferMap[path]; ok {
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

			reporter.addFileTransfer(transfer, block)

			if nextOffset, ok2 := reporter.NextFileOffsetMap[path]; ok2 {
				if nextOffset == offset {
					// move next
					reporter.NextFileOffsetMap[path] = offset + length
				} else {
					// random access
					transfer.SequentialAccess = false
				}
			}
		}
	}
}

// addFileTransfer adds the file transfer to the list
func (reporter *MonitoringReporter) addFileTransfer(transfer *monitor_types.ReportFileTransfer, block monitor_types.FileBlock) {
	if len(transfer.TransferBlocks) < MaxTransferBlockLen {
		// add to last
		transfer.TransferBlocks = append(transfer.TransferBlocks, block)
	}
}
