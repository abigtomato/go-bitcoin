package blockchain

import (
	"log"
	"fmt"
	"bytes"
	"errors"
	"crypto/sha256"
	"github.com/boltdb/bolt"
)

// 区块链结构
type BlockChain struct {
	db 		*bolt.DB	// bolt数据库
	tail 	[]byte		// 最后一个区块的Hash
}

const (
	// 数据库文件名
	blockChainDB = "./data/blockChain.db"
	// 抽屉名
	blockBucket = "blockBucket"
	// 链上最后区块Hash的Key
	lastHashKey = "lastHashKey"
)

// 生成创世区块
func GenesisBlock(address string) *Block {
	coinbase := NewCoinbaseTX(address, "创世区块")
	return NewBlock([]*Transaction{coinbase}, []byte{})
}

// 创建区块链(生成创世区块并持久化到数据库)
func NewBlockChain(address string) *BlockChain {
	var lastHash []byte

	db, err := bolt.Open(blockChainDB, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	
	/*	
		数据库存储结构:
			Bucket: 存储区块链
			|-- K-V: 存储区块
				|-- Key: 区块的Hash
				|-- Value: 区块序列化后的信息
			|-- 特殊K-V: 存储最后一个区块的Hash
				|-- Key: 固定的字符串"lastHashKey"
				|-- Value: 最后一个区块的Hash
	 */
	db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(blockBucket))
		if bucket == nil {
			// 若不存在抽屉(Bucket)，则创建一个来存储区块链
			bucket, err = tx.CreateBucket([]byte(blockBucket))
			if err != nil {
				log.Fatal(err)
			}
			
			// 生成并持久化创世块
			genesisBlock := GenesisBlock(address)
			bucket.Put(genesisBlock.Hash, Serialize(genesisBlock))
			// 单独存入特殊的键值对，链上最后一个区块的Hash
			bucket.Put([]byte(lastHashKey), genesisBlock.Hash)
			
			lastHash = genesisBlock.Hash
		} else {
			// 若已经存在bucket，则直接获取lastHash
			lastHash = bucket.Get([]byte(lastHashKey))
		}

		return nil
	})
	
	return &BlockChain{db: db, tail: lastHash}
}

// 获取区块链结构
func GetBlockChain() *BlockChain {
	var lastHash []byte

	db, err := bolt.Open(blockChainDB, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(blockBucket))
		if bucket != nil {
			// 直接取出lastHash
			lastHash = bucket.Get([]byte(lastHashKey))
		}
		return nil
	})

	if lastHash != nil {
		return &BlockChain{db, lastHash}
	}

	// 若区块链并未创建，则本次关闭bolt数据库连接
	db.Close()
	return nil
}

// 在链上添加新的区块
func (this *BlockChain) AddBlock(txs []*Transaction) {
	// 1. 校验本次交易
	for _, tx := range txs {
		prevTXs := this.FindPrevTransaction(tx.TXInputs)
		if !tx.Verify(prevTXs) {
			fmt.Println("矿工发现此笔交易无效!")
			return
		}
	}
	
	// 2. 持久化到bolt数据库
	this.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(blockBucket))
		if bucket == nil {
			log.Panic("Bucket不存在")
		}

		block := NewBlock(txs, this.tail)
		this.tail = block.Hash
		
		bucket.Put(block.Hash, Serialize(block))
		bucket.Put([]byte(lastHashKey), block.Hash)
		
		return nil
	})
}

// 通过地址的公钥Hash查找其对应的UTXO(未消费的output，也就是该地址的可用余额)
func (this *BlockChain) FindUTXOs(pubKeyHash []byte) []TXOutput {
	// 符合指定地址的UTXO集合
	var utxos []TXOutput
	
	for _, tx := range this.FindUTXOTransaction(pubKeyHash) {
		for _, output := range tx.TXOutputs {
			// 过滤出和此地址对应的output(pubKeyHash相匹配)
			if bytes.Equal(pubKeyHash, output.PubKeyHash) {
				utxos = append(utxos, output)
			}
		}
	}

	return utxos
}

// 查找满足本次交易金额的UTXOs(根据付款方的公钥Hash查找)
func (this *BlockChain) FindNeedUTXOs(senderPubKeyHash []byte, amount float64) (map[string][]int64, float64) {
	// 满足本次交易的BTC数量	
	var calc float64
	// 满足交易的UTXO集合(结构: 交易ID做为key，output索引的集合做为value)
	utxos := make(map[string][]int64)

	for _, tx := range this.FindUTXOTransaction(senderPubKeyHash) {
		for i, output := range tx.TXOutputs {
			if bytes.Equal(senderPubKeyHash, output.PubKeyHash) {
				// 累加各个output的金额，直到满足本次交易所需要的金额
				if calc < amount {
					calc += output.Value
					utxos[string(tx.TXID)] = append(utxos[string(tx.TXID)], int64(i))
				} else {
					return utxos, calc
				}
			}
		}
	}

	return utxos, calc
}

// 查找所有和指定地址有关的交易(交易中包含地址的有效output)
func (this *BlockChain) FindUTXOTransaction(senderPubKeyHash []byte) []*Transaction {
	// 符合指定address的output
	var txs []*Transaction
	// 已被消费的Output
	spentOutputs := make(map[string][]int64)	// 结构: key为交易ID，value为input所引用的output

	// 1. 遍历整个区块链中的所有区块
	it := this.GetIterator()
	for {		
		block, err := it.Next()

		// 2. 遍历区块中的所有交易
		for _, tx := range block.Transactions {
			// 3. 遍历交易中的所有output
			OUTPUT:
			for i, output := range tx.TXOutputs {
				// 4. 过滤已被消费的output(已被input引用的output就是已被消费的)
				if spentOutputs[string(tx.TXID)] != nil {
					for _, j := range spentOutputs[string(tx.TXID)] {
						if int64(i) == j {
							continue OUTPUT
						}
					}
				}
				
				// 5. 过滤出和地址的output相关的交易
				if bytes.Equal(senderPubKeyHash, output.PubKeyHash) {
					txs = append(txs, tx)
				}
			}
			
			// 6. 遍历交易中的input(根据input查找出该地址所有已被消费的output)
			if !tx.IsCoinbase() {
				for _, input := range tx.TXInputs {
					hash := sha256.Sum256(input.PubKey)
					// 过滤出和该地址相关的input
					if bytes.Equal(hash[:], senderPubKeyHash) {
						spentOutputs[string(input.TXid)] = append(spentOutputs[string(input.TXid)], input.Index)
					}
				}
			}
		}

		if err != nil {
			log.Println(err)
			break
		}
	}

	return txs
}

// 根据交易ID在整个区块链中查找原交易结构
func (this *BlockChain) FindTransactionByTXid(TXid []byte) (Transaction, error) {	
	it := this.GetIterator()
	
	for {
		block, err := it.Next()
		
		for _, tx := range block.Transactions {
			if bytes.Equal(tx.TXID, TXid) {
				return *tx, nil
			}
		}

		if err != nil {
			log.Panic(err)
			break
		}
	}

	return Transaction{}, errors.New("交易未找到!")
}

// 从整个区块链中查找包含inputs所引用的output的交易
func (this *BlockChain) FindPrevTransaction(inputs []TXInput) map[string]Transaction {
	// 符合的交易集合(key为交易ID，value为交易结构)
	prevTXs := make(map[string]Transaction)	
	
	for _, input := range inputs {
		tx, err := this.FindTransactionByTXid(input.TXid)
		if err != nil {
			log.Panic(err)
		}

		if _, ok := prevTXs[string(input.TXid)]; !ok {
			prevTXs[string(input.TXid)] = tx
		}
	}
	
	return prevTXs
}
