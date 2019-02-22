package main

import (
	"os"
	"fmt"
	"log"
	"time"
	"strconv"
	bc "go_code/learn-go/bitcoin/blockchain"
)

// 交互式界面结构
type CLI struct {
	chain	*bc.BlockChain
}

// 交互式显示信息
const Usage = `
	createBlockChain --miner MINER	"创建区块链，指定矿工生成创世块"
	printChain	"从尾区块开始正向打印区块链"
	getBalance --address ADDRESS	"获取指定地址的余额"
	send --from FROM --to TO --amount AMOUNT --miner MINER --data DATA	"指定交易双方建立一笔交易"
	newWallet "创建一个新的钱包(包含公钥私钥)"
	getAddress "列举所有的地址"
`

// 生成创世块
func (this *CLI) CreateBlockChain(miner string) *bc.BlockChain {
	return bc.NewBlockChain(miner)
}

// 打印整个区块链
func (this *CLI) PrintBlockChain() {
	it := this.chain.GetIterator()
	
	for {
		block, err := it.Next()

		// 打印区块信息
		fmt.Printf("==================================\n")
		fmt.Printf("|| 版本号: %d\n", block.Version)
		fmt.Printf("|| 前置区块哈希: %x\n", block.PrevHash)
		fmt.Printf("|| 梅克尔根: %x\n", block.MerkelRoot)
		fmt.Printf("|| 时间戳: %s\n", time.Unix(int64(block.TimeStamp), 0).Format("2006-01-02 15:04:05"))
		fmt.Printf("|| 难度值: %d\n", block.Difficulty)
		fmt.Printf("|| 随机数: %d\n", block.Nonce)
		fmt.Printf("|| 当前区块哈希值: %x\n", block.Hash)

		// 打印区块中每笔交易的信息
		for _, tx := range block.Transactions {
			fmt.Println(tx)
		}

		if err != nil {
			log.Println(err)
			break
		}
	}
}

// 获取地址的可用余额
func (this *CLI) GetBalance(address string) {
	// 1. 校验地址(防止地址的后4位checksum校验码被篡改)
	if !bc.IsValidAddress(address) {
		fmt.Printf("地址无效: %s\n", address)
		return
	}

	// 2. 通过地址返推公钥Hash
	pubKeyHash := bc.GetPubKeyFromAddress(address)
	
	// 3. 通过公钥Hash查找UTXO
	utxos := this.chain.FindUTXOs(pubKeyHash)

	// 4. 计算可用余额
	total := 0.0
	for _, utxo := range utxos {
		total += utxo.Value
	}

	fmt.Printf("%s 的余额为: %f\n", address, total)
}

// 转账功能实现
func (this *CLI) Send(from, to string, amount float64, miner, data string) {
	// 1. 校验地址
	if !bc.IsValidAddress(from) {
		fmt.Printf("地址无效: %s\n", from)
		return
	}
	if !bc.IsValidAddress(to) {
		fmt.Printf("地址无效: %s\n", to)
		return
	}
	if !bc.IsValidAddress(miner) {
		fmt.Printf("地址无效: %s\n", miner)
		return
	}

	// 2. 创建一笔挖矿交易
	coinbase := bc.NewCoinbaseTX(miner, data)
	
	// 3. 创建一笔普通交易
	tx := bc.NewTransaction(from, to, amount, this.chain)
	if tx == nil {
		fmt.Println("交易失败！")
		return
	}

	// 4. 创建新的区块
	this.chain.AddBlock([]*bc.Transaction{coinbase, tx})
}

// 生成新的钱包
func (this *CLI) NewWallet() {
	wallets := bc.NewWallets()
	address := wallets.AddWallet()
	
	fmt.Printf("生成地址: %s\n", address)
}

// 获取全部地址
func (this *CLI) GetAllAddress() {
	wallets := bc.NewWallets()
	
	for _, address := range wallets.GetAllAddress() {
		fmt.Printf("地址: %s\n", address)
	}
}

// 启动交互式界面
func (this *CLI) Run() {
	args := os.Args
	if len(args) < 2 {
		fmt.Println("需要参数!")
		fmt.Println(Usage)
		return
	}

	if chain := bc.GetBlockChain(); chain != nil {
		this.chain = chain
	}

	switch args[1] {
		case "createBlockChain":
			if this.chain != nil {
				fmt.Println("区块链已创建!")
				fmt.Println(Usage)
				return
			}
			
			fmt.Println("创建区块链.....................")
			if len(args) == 4 && args[2] == "--miner" {	
				miner := args[3]
				this.chain = this.CreateBlockChain(miner)
			} else {
				fmt.Println("参数错误!")
				fmt.Println(Usage)
			}
		case "printChain":
			if this.chain == nil {
				fmt.Println("未创建区块链!")
				fmt.Println(Usage)
				return
			}
			
			fmt.Println("打印区块.......................")
			this.PrintBlockChain()
		case "getBalance":
			if this.chain == nil {
				fmt.Println("未创建区块链!")
				fmt.Println(Usage)
				return
			}
			
			fmt.Println("获取余额.......................")
			if len(args) == 4 && args[2] == "--address" {
				address := args[3]
				this.GetBalance(address)
			} else {
				fmt.Println("参数错误!")
				fmt.Println(Usage)
			}
		case "send":
			if this.chain == nil {
				fmt.Println("未创建区块链!")
				fmt.Println(Usage)
				return
			}
			
			fmt.Println("开始转账.......................")
			if len(args) != 12 {
				fmt.Println("参数错误!")
				fmt.Println(Usage)
				return
			}
			from := args[3]
			to := args[5]
			amount, _ := strconv.ParseFloat(args[7], 64)
			miner := args[9]
			data := args[11]
			this.Send(from, to, amount, miner, data)
		case "newWallet":
			fmt.Println("钱包生成.....................")
			this.NewWallet()
		case "getAddress":
			fmt.Println("地址列表.....................")
			this.GetAllAddress()
		default:
			fmt.Println("命令无效!")
			fmt.Println(Usage)
	}
}

func main() {
	cli := &CLI{}
	cli.Run()
}