package blockchain

import (
	"log"
	"bytes"
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/elliptic"
	"golang.org/x/crypto/ripemd160"
	"github.com/btcsuite/btcutil/base58"
)

// 钱包结构(保存非对称加密的密钥对)
type Wallet struct {
	Private		*ecdsa.PrivateKey		// 私钥(使用椭圆曲线算法)
	PubKey 		[]byte					// 公钥(为了网络传输速度，只存储X和Y拼接的字符串，在校验端重新拆分)
}

// 生成钱包
func NewWallet() *Wallet {
	// 1. 使用椭圆曲线算法生成私钥
	curve := elliptic.P256()	// 生成曲线
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}

	// 2. 获取公钥
	pubKeyOrig := privateKey.PublicKey	// 取出公钥
	pubKeyStr := append(pubKeyOrig.X.Bytes(), pubKeyOrig.Y.Bytes()...)	// 拼接便于网络传输的公钥字符串
	
	return &Wallet{
		Private: privateKey,
		PubKey: pubKeyStr,
	}
}

// 生成地址
func (this *Wallet) NewAddress() string {
	// 1. 获取公钥
	pubKey := this.PubKey

	// 2. 对公钥做Hash和ripemd160算法
	rip160HashValue := HashPubKey(pubKey)

	// 3. 拼接version(1byte)和公钥Hash(20byte)生成payload(21byte)
	version := byte(00)
	payload := append([]byte{version}, rip160HashValue...)

	// 4. 对payload进行checksum，生成4byte的校验码
	checkCode := CheckSum(payload)

	// 5. 将校验码(4byte)与payload(21byte)进行拼接(25byte)
	payload = append(payload, checkCode...)

	// 7. 对拼接好的字节流做base58算法生成地址
	return base58.Encode(payload)	// go get -v github.com/btcsuite/btcutil/base58
}

// 生成公钥Hash
func HashPubKey(data []byte) []byte {
	hash := sha256.Sum256(data)

	// 对公钥Hash做ripemd160算法
	rip160hasher := ripemd160.New()
	_, err := rip160hasher.Write(hash[:])
	if err != nil {
		log.Panic(err)
	}
	rip160HashValue := rip160hasher.Sum(nil)
	
	return rip160HashValue
}

// 生成checksum校验码
func CheckSum(payload []byte) []byte {
	// 1. 做两次Hash
	hash1 := sha256.Sum256(payload)
	hash2 := sha256.Sum256(hash1[:])
	
	// 2. 截取前4字节校验码
	return hash2[:4]
}

/* 
	校验地址:
	1. 因为进行UTXO查询时会只会比较pubKeyHash，不会涉及到后4位的checksum校验码；
	2. 只要前21位相同，就算是随意填写checksum校验码也会被误认为是同一个地址；
	3. 所以要在进行UTXO相关操作前对前21byte重新计算一遍checksum，若与传入地址的checksum相同，则地址无误，反之有误。
 */
func IsValidAddress(address string) bool {
	// 1. base58解码
	addressByte := base58.Decode(address)
	if len(addressByte) < 4 {
		return false
	}

	// 2. 抽取payload(前21byte)
	payload := addressByte[:len(addressByte)-4]
	
	// 3. 抽取传入的checksum(后4byte)
	checkSum1 := addressByte[len(addressByte)-4:]

	// 4. 使用payload重新计算出checksum
	checkSum2 := CheckSum(payload)

	// 5. 比较两次checksum的一致性
	return bytes.Equal(checkSum1, checkSum2)
}