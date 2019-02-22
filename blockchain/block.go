package blockchain

import (
	"log"
	"time"
	"bytes"
	"encoding/gob"
	"crypto/sha256"
	"encoding/binary"
)

// 区块结构
type Block struct {
	Version			uint64			// 版本号
	PrevHash		[]byte			// 前区块哈希
	MerkleRoot		[]byte			// 梅克尔根
	TimeStamp		uint64			// 时间戳
	Difficulty		uint64			// 难度值
	Nonce			uint64			// 随机数

	Hash 			[]byte			// 当前区块哈希
	Transactions	[]*Transaction	// 交易数据
}

// 通过挖矿产生新区块
func NewBlock(txs []*Transaction, prevBlockHash []byte) *Block {
	// 1. 初始化区块结构
	block := &Block{
		Version: 00,
		PrevHash: prevBlockHash,
		TimeStamp: uint64(time.Now().Unix()),
		Difficulty: 0,
		Transactions: txs,
	}

	// 2. 计算梅克尔根
	block.MerkleRoot = block.MakeMerkleRoot()

	// 3. 进行挖矿，产生区块的Hash和Nonce(由矿工完成)
	pow := NewProofOfWork(block)
	block.Hash, block.Nonce = pow.Run()

	return block
}

// 计算梅克尔根
func (this *Block) MakeMerkleRoot() []byte {
	// 1. 将区块中的所有交易做Hash处理
	var txHashs [][]byte
	for _, tx := range this.Transactions {
		txHashs = append(txHashs, tx.TXID)
	}

	// 2. 计算梅克尔树
	var alones [][]byte	// 用于存储不能进行串联的单节点
	for {
		// 2.1 设置退出条件: 计算到整个集合只有一个值为止(最少需要2个值串联)
		if len(txHashs) == 1 {
			break
		}

		// 2.2 抽取出不能进行串联的单独节点
		if len(txHashs) % 2 != 0 {
			alones = append(alones, txHashs[len(txHashs) - 1])
			txHashs = txHashs[:len(txHashs) - 1]
		}
		
		// 2.3 每个节点和相邻节点串联后计算哈希
		var tmp [][]byte
		for i := 0; i < len(txHashs); i += 2 {
			var merge []byte
			merge = append(merge, txHashs[i]...) 
			merge = append(merge, txHashs[i + 1]...)
			
			hash := sha256.Sum256(merge)
			tmp = append(tmp, hash[:])
		}
		txHashs = tmp
	}

	// 3. 和剩余的独立节点进行计算(若存在)
	if len(alones) > 0 {
		var result []byte
		result = append(result, txHashs[0]...)

		for _, elem := range alones {
			result = append(result, elem...)
		}

		resHash := sha256.Sum256(result)
		return resHash[:]
	}

	return txHashs[0]
}

// 工具函数: 序列化
func Serialize(block *Block) []byte {
	var buffer bytes.Buffer
	
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(block); err != nil {
		log.Panic(err)
	}

	return buffer.Bytes()
}

// 工具函数: 反序列化
func DeSerialize(data []byte, block *Block) {
	decoder := gob.NewDecoder(bytes.NewReader(data))
	
	if err := decoder.Decode(block); err != nil {
		log.Panic(err)
	}
}

// 工具函数: uint64转[]byte
func Uint64ToByte(num uint64) []byte {
	var buffer bytes.Buffer
	
	/* 
		binary包: 
			实现了简单的数字与字节序列的转换以及变长值的编解码
		binary.BigEndian:
			大端字节序的实现
		binary.Write: 
		   将num的binary编码格式写入buffer，参数2指定写入数据的字节序，写入结构体时，名字中有'_'的字段会置为0 
	 */
	if err := binary.Write(&buffer, binary.BigEndian, num); err != nil {
		log.Panic(err)
	}

	return buffer.Bytes()
}
