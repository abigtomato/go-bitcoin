package blockchain

import (
	"fmt"
	"bytes"
	"strconv"
	"math/big"
	"crypto/sha256"
)

/* 
	POW工作量证明结构:
	1. 要求运行一个哈希算法，找到一个小于给定的哈希(该哈希值由N个前导0构成，0的个数取决于网络的难度值)的哈希值；
	2. 哈希算法: sha256(区块头信息+随机值)。
 */
type ProofOfWork struct {
	block 		*Block			// 区块
	target 		*big.Int		// 目标值
}

// 创建工作量证明
func NewProofOfWork(block *Block) *ProofOfWork {
	// 1. 设定难度值(真实环境由比特币系统设定)，前导0越多越复杂
	targetStr := "0000100000000000000000000000000000000000000000000000000000000000"
	difficulty, _ := strconv.ParseUint(targetStr, 16, 64)
	block.Difficulty = difficulty
	
	tmpInt := big.Int{}	// big.Int类型代表多精度的整数，零值代表数字0
	tmpInt.SetString(targetStr, 16)	// 将tmpInt设为targetStr代表的值，16表示十六进制整数的形式表示

	// 2. 封装POW结构
	return &ProofOfWork{
		block: block,
		target: &tmpInt,
	}
}

/*	
	挖矿函数:
	1. 提供计算区块Hash的功能；
	2. 挖矿过程就是不断变换随机值，然后和区块头组合进行Hash运算，直到满足难度值的要求。
 */
func (this *ProofOfWork) Run() ([]byte, uint64) {
	var hash [32]byte	// 结果Hash
	var nonce uint64	// 随机数

	for {
		// 1. 用于哈希运算的区块头信息和随机数
		blockInfo := bytes.Join([][]byte{
			Uint64ToByte(this.block.Version),
			this.block.PrevHash,
			this.block.MerkleRoot,
			Uint64ToByte(this.block.TimeStamp),
			Uint64ToByte(this.block.Difficulty),
			Uint64ToByte(nonce),
		}, []byte{})

		// 2. 进行哈希运算
		hash = sha256.Sum256(blockInfo)
		tmpInt := big.Int{}
		// tmpInt.SetBytes: 将hash[:]视为一个大端在前的无符号整数，将tmpInt设为该值，并返回tmpInt
		tmpInt.SetBytes(hash[:])
		
		// tmpInt.Cmp: 比较x和y的大小。x<y时返回-1；x>y时返回+1；否则返回0
		if tmpInt.Cmp(this.target) == -1 {
			fmt.Printf("挖矿成功! 区块的Hash为: %x, 随机值Nonce为: %d\n", hash, nonce)
			break
		} else {
			nonce ++
		}
	}
	
	return hash[:], nonce
}
