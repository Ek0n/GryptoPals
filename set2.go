package GryptoPals

import "crypto/cipher"

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
