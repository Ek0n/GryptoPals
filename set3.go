package GryptoPals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"unicode"
)

func newCBCPaddingOracles(plaintext []byte) (
	encryptMessage func() []byte,
	checkMessagePadding func(message []byte) bool,
) {
	key := make([]byte, 16)
	rand.Read(key)
	b, _ := aes.NewCipher(key)
	encryptMessage = func() []byte {
		iv := make([]byte, 16)
		rand.Read(iv)

		ct := encryptCBC(padPKCS7(plaintext, 16), b, iv)
		return append(iv, ct...)
	}

	checkMessagePadding = func(message []byte) bool {
		iv, msg := message[:16], message[16:]
		res := unpadPKCS7(decryptCBC(msg, b, iv))
		return res != nil
	}

	return
}

func attackCBCPaddingOracle(ct []byte, checkMessagePadding func(ct []byte) bool) []byte {
	findNextByte := func(known, iv, block []byte) []byte {
		if len(block) != 16 || len(iv) != 16 || len(known) >= 16 {
			panic("wrong lengths for findNextByte")
		}
		payload := make([]byte, 32)
		copy(payload[16:], block)
		plaintext := append([]byte{0}, known...)

		for p := 0; p < 256; p++ {
			copy(payload, iv)
			plaintext[0] = byte(p)

			// neuter the plaintext bytes
			for i := range plaintext {
				payload[len(payload)-1-16-i] ^= plaintext[len(plaintext)-1-i]
			}

			// apply valid padding
			for i := range plaintext {
				payload[len(payload)-1-16-i] ^= byte(len(plaintext))
			}

			// check we actually changed something
			if bytes.Equal(payload[:16], iv) {
				continue
			}

			if checkMessagePadding(payload) {
				return plaintext
			}
		}

		// if the only one that works is not changing anything,
		// there's already a padding of len len(plaintext)
		plaintext[0] = byte(len(plaintext))
		for _, c := range plaintext {
			if c != byte(len(plaintext)) {
				// TODO: make test case for this
				plaintext[1] ^= byte(len(plaintext))
				return plaintext[1:] // correct and retry
			}
		}
		return plaintext
	}

	if len(ct)%16 != 0 {
		panic("attackCBCPaddingOracle: invalid ciphertext length")
	}

	var plaintext []byte
	for b := 0; b < len(ct)/16-1; b++ {
		var known []byte
		blockStart := len(ct) - b*16 - 16
		block := ct[blockStart : blockStart+16]
		iv := ct[blockStart-16 : blockStart]
		for len(known) < 16 {
			known = findNextByte(known, iv, block)
		}
		plaintext = append(known, plaintext...)
	}

	return plaintext
}

func encryptCTR(src []byte, b cipher.Block, nonce []byte) []byte {
	if len(nonce) >= b.BlockSize() {
		panic("nonce should be shorter than blocksize")
	}
	input, output := make([]byte, b.BlockSize()), make([]byte, b.BlockSize())
	copy(input, nonce)
	var dst []byte
	for i := 0; i < len(src); i += b.BlockSize() {
		b.Encrypt(output, input)
		dst = append(dst, xor(output, src[i:])...)

		j := len(nonce)
		for {
			input[j]++
			if input[j] != 0 {
				break
			}
			j++
		}
	}
	return dst
}

var decryptCTR = encryptCTR

func newFixedNonceCTROracle() func(msg []byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)
	b, _ := aes.NewCipher(key)
	nonce := make([]byte, 8)
	rand.Read(nonce)
	return func(msg []byte) []byte {
		return encryptCTR(msg, b, nonce)
	}
}

func findFixedNonceCTRKeystream(ciphertexts [][]byte, corpus map[rune]float64) []byte {
	uppercaseCorpus := make(map[rune]float64)
	for c, s := range corpus {
		if !unicode.IsUpper(c) {
			continue
		}
		uppercaseCorpus[c] = s
	}

	column := make([]byte, len(ciphertexts))
	var maxLen int
	for _, c := range ciphertexts {
		if len(c) > maxLen {
			maxLen = len(c)
		}
	}
	keystream := make([]byte, maxLen)
	for col := 0; col < maxLen; col++ {
		var colLen int
		for _, c := range ciphertexts {
			if col >= len(c) {
				continue
			}
			column[colLen] = c[col]
			colLen++
		}

		c := corpus
		if col == 0 {
			c = uppercaseCorpus
		}
		_, k, _ := findSingleXORKey(column[:colLen], c)
		keystream[col] = k
	}
	return keystream
}

type MT19937 struct {
	index int
	mt    [624]uint32
}

func NewMT19937(seed uint32) *MT19937 {
	ret := &MT19937{
		index: 624,
	}

	ret.mt[0] = seed
	for i := 1; i < ret.index; i++ {
		ret.mt[i] = 1812433253*(ret.mt[i-1]^ret.mt[i-1]>>30) + uint32(i)
	}

	return ret
}

func (mt *MT19937) ExtractNumber() uint32 {
	if mt.index >= 624 {
		mt.twist()
	}

	y := mt.mt[mt.index]

	y ^= y >> 11
	y ^= y << 7 & 2636928640
	y ^= y << 15 & 4022730752
	y ^= y >> 18

	mt.index++
	return y
}

func (mt *MT19937) twist() {
	for i := range mt.mt {
		y := (mt.mt[i] & 0x80000000) + (mt.mt[(i+1)%624] & 0x7fffffff)
		mt.mt[i] = mt.mt[(i+397)%624] ^ y>>1
		if y%2 != 0 {
			mt.mt[i] ^= 0x9908b0df
		}
	}

	mt.index = 0
}
