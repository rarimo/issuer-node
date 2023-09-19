package domain

type MerkleTreeNode struct {
	MTID   int64
	Key    []byte
	Type   uint8
	ChildL []byte
	ChildR []byte
}
