package blockchain

import (
	"log"
	"bytes"
	"io/ioutil"
	"encoding/gob"
	"crypto/elliptic"
	"github.com/btcsuite/btcutil/base58"
)

func init() {
	/* 
		1. 若使用gob编码/解码的类型是interface或struce有interface{}字段的时候，需要在gob中注册
		2. 钱包中使用的椭圆曲线elliptic.Curve为interface类型
	 */
	gob.Register(elliptic.P256())
}

// 钱包容器结构
type Wallets struct {
	WalletsMap	map[string]*Wallet	// key为地址，value为钱包
}

// 生成/获取钱包容器
func NewWallets() *Wallets {
	wallets := LoadFile()
	
	// 若钱包容器存在则是获取功能，若不存在则是创建功能
	if wallets == nil {
		wallets = &Wallets{
			WalletsMap: make(map[string]*Wallet),
		}
		wallets.SaveToFile()
	}
	
	return wallets
}

// 工具函数: 加载持久化到磁盘的钱包文件
func LoadFile() *Wallets {
	content, err := ioutil.ReadFile("wallet.dat")
	if err != nil {
		log.Println("创建钱包容器")
		return nil
	}

	var wallets Wallets
	decoder := gob.NewDecoder(bytes.NewReader(content))
	err = decoder.Decode(&wallets)
	if err != nil {
		log.Panic(err)
	}

	return &wallets
}

// 添加一个新的钱包到容器
func (this *Wallets) AddWallet() string {
	// 1. 生成新钱包新地址 
	wallet := NewWallet()
	address := wallet.NewAddress()

	// 2. 添加钱包并持久化
	this.WalletsMap[address] = wallet
	this.SaveToFile()
	
	return address
}

// 持久化钱包容器到磁盘
func (this *Wallets) SaveToFile() {
	var buffer bytes.Buffer
	
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(this); err != nil {
		log.Panic(err)
	}

	if err := ioutil.WriteFile("wallet.dat", buffer.Bytes(), 0600); err != nil {
		log.Panic(err)
	}
}

// 获取全部的地址信息
func (this *Wallets) GetAllAddress() []string {
	var addresses []string

	for address := range this.WalletsMap {
		addresses = append(addresses, address)
	}

	return addresses
}

// 根据地址反推出公钥Hash
func GetPubKeyFromAddress(address string) []byte {
	// 1. base58解码
	addressByte := base58.Decode(address)
	
	// 2. 切断掉前1byte(version)和后4byte(checksum校验码)
	len := len(addressByte)
	pubKeyHash := addressByte[1:len-4]
	
	return pubKeyHash
}
