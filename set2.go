package GryptoPals

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	mathrand "math/rand"
)

func padPKCS7(in []byte, size int) []byte {
	if size >= 256 {
		panic("can't pad to size higher than 255")
	}
	padLen := size - len(in)%size
	res := make([]byte, len(in)+padLen)
	copy(res, in)
	for i := len(in); i < len(res); i++ {
		res[i] = byte(padLen)
	}
	return res
}

func encryptCBC(src []byte, b cipher.Block, iv []byte) []byte {
	bs := b.BlockSize()
	if len(src)%bs != 0 {
		panic("Wrong input length")
	}
	if len(iv)%bs != 0 {
		panic("Wrong iv length")
	}
	out := make([]byte, len(src))
	prev := iv
	for i := 0; i < len(src)/bs; i++ {
		copy(out[i*bs:], xor(src[i*bs:(i+1)*bs], prev))
		b.Encrypt(out[i*bs:], out[i*bs:])
		prev = out[i*bs : (i+1)*bs]
	}
	return out
}

func decryptCBC(src []byte, b cipher.Block, iv []byte) []byte {
	bs := b.BlockSize()
	if len(src)%bs != 0 {
		panic("Wrong input length")
	}
	if len(iv)%bs != 0 {
		panic("Wrong iv length")
	}
	out := make([]byte, len(src))
	prev := iv
	buf := make([]byte, bs)
	for i := 0; i < len(src)/bs; i++ {
		b.Decrypt(buf, src[i*bs:])
		copy(out[i*bs:], xor(buf, prev))
		prev = src[i*bs : (i+1)*bs]
	}
	return out
}

func encryptECB(in []byte, b cipher.Block) []byte {
	if len(in)%b.BlockSize() != 0 {
		panic("EncryptECB: length not a multiple of BlockSize")
	}
	out := make([]byte, len(in))
	for i := 0; i < len(in); i += b.BlockSize() {
		b.Encrypt(out[i:], in[i:])
	}
	return out
}

func newECBCBCOracle() func([]byte) []byte {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		panic("Failed to read from rand")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		panic("Failed to create new AES cypher")
	}

	return func(in []byte) []byte {
		prefix := make([]byte, mathrand.Intn(5)+5)
		_, err := rand.Read(prefix)
		if err != nil {
			panic("Failed to read from rand")
		}
		suffix := make([]byte, mathrand.Intn(5)+5)
		_, err = rand.Read(suffix)
		if err != nil {
			panic("Failed to read from rand")
		}

		msg := padPKCS7(append(append(prefix, in...), suffix...), 16)

		if mathrand.Intn(10)%2 == 0 {
			iv := make([]byte, 16)
			_, err := rand.Read(iv)
			if err != nil {
				panic("Failed to read from rand")
			}
			return encryptCBC(msg, b, iv)
		}

		return encryptECB(in, b)
	}
}
