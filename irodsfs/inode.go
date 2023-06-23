package irodsfs

import "github.com/cyverse/irodsfs/utils"

func getInodeIDFromEntryID(id int64) uint64 {
	if id < 0 {
		// virtual
		return uint64(utils.MaxInt) + uint64(-1*id)
	}

	return uint64(id)
}
