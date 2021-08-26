package utils

type BlockID int64

// FileBlockHelper ...
type FileBlockHelper struct {
	BlockSize int
	FileSize  int64
}

// GetBlockNum returns the number of blocks
func (helper *FileBlockHelper) GetBlockNum() int64 {
	blockNum := helper.FileSize / int64(helper.BlockSize)
	if helper.FileSize%int64(helper.BlockSize) != 0 {
		blockNum++
	}
	return blockNum
}

// GetBlockIDForOffset returns block index
func (helper *FileBlockHelper) GetBlockIDForOffset(offset int64) BlockID {
	blockID := offset / int64(helper.BlockSize)
	return BlockID(blockID)
}

// GetBlockStartOffsetForBlockID returns block start offset
func (helper *FileBlockHelper) GetBlockStartOffsetForBlockID(blockID BlockID) int64 {
	return int64(blockID) * int64(helper.BlockSize)
}

// GetBlockSizeForBlockID returns block size
func (helper *FileBlockHelper) GetBlockSizeForBlockID(blockID BlockID) int {
	return int(helper.FileSize - int64(blockID)*int64(helper.BlockSize))
}

// GetInBlockOffsetAndLength returns in-block offset and in-block length
func (helper *FileBlockHelper) GetInBlockOffsetAndLength(offset int64, length int) (int, int) {
	blockid := helper.GetBlockIDForOffset(offset)
	blockStartOffset := helper.GetBlockStartOffsetForBlockID(blockid)
	inBlockOffset := int(offset - blockStartOffset)
	inBlockLength := length
	if inBlockLength > (helper.BlockSize - inBlockOffset) {
		inBlockLength = helper.BlockSize - inBlockOffset
	}

	return inBlockOffset, inBlockLength

}

// GetFirstAndLastBlockIDForRW returns first and last block id for read or write
func (helper *FileBlockHelper) GetFirstAndLastBlockIDForRW(offset int64, length int) (BlockID, BlockID) {
	first := helper.GetBlockIDForOffset(offset)
	last := helper.GetBlockIDForOffset(offset + int64(length-1))
	if last < first {
		last = first
	}
	return first, last
}
