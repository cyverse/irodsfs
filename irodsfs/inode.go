package irodsfs

import "github.com/cyverse/irodsfs/utils"

var (
	dummyInodeID    uint64            = 100000
	dummyInodeIDMap map[string]uint64 = map[string]uint64{}
)

func getInodeIDFromEntryID(id int64) uint64 {
	if id < 0 {
		// virtual
		return uint64(utils.MaxInt) + uint64(-1*id)
	}

	return uint64(id)
}

func getDummyInodeID(path string) uint64 {
	if id, ok := dummyInodeIDMap[path]; ok {
		return id
	}

	// not exist
	dummyInodeID++
	id := uint64(utils.MaxInt) + dummyInodeID
	dummyInodeIDMap[path] = id
	return id
}
