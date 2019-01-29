package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"bytes"
	"encoding/binary"
	"encoding/base64"
)

/*

1. EncodingAESKey即消息加解密Key，长度固定为43个字符，从a-z,A-Z,0-9共62个字符中选取。由开发者在创建公众号插件时填写，后也可申请修改。

2.AES密钥： AESKey=Base64_Decode(EncodingAESKey + “=”)，EncodingAESKey尾部填充一个字符的“=”, 用Base64_Decode生成32个字节的AESKey；

3.AES采用CBC模式，秘钥长度为32个字节，数据采用PKCS#7填充；
PKCS#7：K为秘钥字节数（采用32），buf为待加密的内容，N为其字节数。
Buf 需要被填充为K的整数倍。在buf的尾部填充(K-N%K)个字节，每个字节的内容是(K- N%K)。

4.加密的buf由16个字节的随机字符串、4个字节的msg_len(网络字节序)、msg和AESKey(32个字节)。
AESKey = Base64_Decode(EncodingAESKey + “=”)
*/

// 把整数n格式化成4字节的网络字节序
func encodeNetworkByteOrder(b []byte, n uint32) {
	b[0] = byte(n >> 24)
	b[1] = byte(n >> 16)
	b[2] = byte(n >> 8)
	b[3] = byte(n)
}

// 从4字节的网络字节序里解析出整数
func decodeNetworkByteOrder(b []byte) (n uint32) {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

const (
	BLOCK_SIZE = 32             // PKCS#7  :K为秘钥字节数（采用32）
	BLOCK_MASK = BLOCK_SIZE - 1 // BLOCK_SIZE 为 2^n 时, 可以用mask获取针对BLOCK_SIZE的余数
)

//消息加密 rawXMLMsg 作为上述msg,消息长度不包含appid，appid可以加入，也可以为空
func AESEncryptMsg(random, rawXMLMsg []byte, appId string, aesKey []byte) (ciphertext []byte) {
	appIdOffset := 20 + len(rawXMLMsg)
	contentLen := appIdOffset + len(appId)

	//需要填充的内容的字节值 ：N%K == N&(K-1) ：其中K为2的整数幂
	amountToPad := BLOCK_SIZE - contentLen&BLOCK_MASK

	plaintextLen := contentLen + amountToPad

	plaintext := make([]byte, plaintextLen)

	// 拼接
	copy(plaintext[:16], random)
	encodeNetworkByteOrder(plaintext[16:20], uint32(len(rawXMLMsg)))
	copy(plaintext[20:], rawXMLMsg)
	copy(plaintext[appIdOffset:], appId)

	// PKCS#7 补位
	for i := contentLen; i < plaintextLen; i++ {
		plaintext[i] = byte(amountToPad)
	}

	//加密
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	cipher.NewCBCEncrypter(block, aesKey[:16]).CryptBlocks(plaintext, plaintext)

	ciphertext = plaintext
	return
}

// ciphertext = AES_Encrypt[random(16B) + msg_len(4B) + rawXMLMsg + appId]
func AESDecryptMsg(ciphertext []byte, aesKey []byte) (random, rawXMLMsg, appId []byte, err error) {
	if len(ciphertext) < BLOCK_SIZE {
		err = fmt.Errorf("the length of ciphertext too short: %d", len(ciphertext))
		return
	}
	// N%K == N&(K-1)
	if len(ciphertext)&BLOCK_MASK != 0 {
		err = fmt.Errorf("ciphertext is not a multiple of the block size, the length is %d", len(ciphertext))
		return
	}

	plaintext := make([]byte, len(ciphertext)) // len(plaintext) >= BLOCK_SIZE
	// 解密
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	cipher.NewCBCDecrypter(block, aesKey[:16]).CryptBlocks(plaintext, ciphertext)

	// PKCS#7去除补位
	amountToPad := int(plaintext[len(plaintext)-1])
	if amountToPad < 1 || amountToPad > BLOCK_SIZE {
		err = fmt.Errorf("the amount to pad is incorrect: %d", amountToPad)
		return
	}
	plaintext = plaintext[:len(plaintext)-amountToPad]

	// len(plaintext) == 16+4+len(rawXMLMsg)+len(appId)
	if len(plaintext) <= 20 {
		err = fmt.Errorf("plaintext too short, the length is %d", len(plaintext))
		return
	}

	rawXMLMsgLen := int(decodeNetworkByteOrder(plaintext[16:20]))
	if rawXMLMsgLen < 0 {
		err = fmt.Errorf("incorrect msg length: %d", rawXMLMsgLen)
		return
	}

	appIdOffset := 20 + rawXMLMsgLen
	if len(plaintext) <= appIdOffset {
		err = fmt.Errorf("msg length too large: %d", rawXMLMsgLen)
		return
	}

	//data[:6:8] 每个数字前都有个冒号， slice内容为data从0到第6位，长度len为6，最大扩充项cap设置为8
	random = plaintext[:16:20]
	rawXMLMsg = plaintext[20:appIdOffset:appIdOffset]
	appId = plaintext[appIdOffset:]

	return
}

//解析加密消息，结果只去掉填充字符
func AESDecryptData(cipherText, aesKey, iv []byte) (rawData []byte, err error) {
	if len(cipherText) < BLOCK_SIZE {
		err = fmt.Errorf("the length of ciphertext too short: %d", len(cipherText))
		return
	}

	plaintext := make([]byte, len(cipherText)) // len(plaintext) >= BLOCK_SIZE

	// 解密
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, cipherText)

	// PKCS#7 去除补位
	amountToPad := int(plaintext[len(plaintext)-1])
	if amountToPad < 1 || amountToPad > BLOCK_SIZE {
		err = fmt.Errorf("the amount to pad is incorrect: %d", amountToPad)
		return
	}
	plaintext = plaintext[:len(plaintext)-amountToPad]

	if len(plaintext) <= 20 {
		err = fmt.Errorf("plaintext too short, the length is %d", len(plaintext))
		return
	}

	rawData = plaintext

	return
}


//解析加密消息，结果只包含rawMsg
func AESDecryptRawMsg(encryped string, aesKey []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryped)
	if nil != err {
		return nil, fmt.Errorf("Base64 decode cipher error: %v", err)
	}

	// decrypt
	block, err := aes.NewCipher(aesKey)
	iv := aesKey[:aes.BlockSize]
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(data, data)

	// decode data
	buf := bytes.NewBuffer(data[16:20])

	var l int32

	//大端处理： 把buf中的字节按BigEndian方式读到 l 中：此时l的值为消息的长度
	binary.Read(buf, binary.BigEndian, &l)
	return data[20: l+20], nil
}
