package GryptoPals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"net/url"
	"strconv"
	"strings"
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

		return encryptECB(msg, b)
	}
}

func newECBSuffixOracle(suffix []byte) func([]byte) []byte {
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
		msg := padPKCS7(append(in, suffix...), 16)
		return encryptECB(msg, b)
	}
}

func recoverECBSuffx(oracle func([]byte) []byte) []byte {
	var bs int
	for blockSize := 2; blockSize < 100; blockSize++ {
		msg := bytes.Repeat([]byte{42}, blockSize*2)
		msg = append(msg, 3)
		if detectECB(oracle(msg)[:blockSize*2], blockSize) {
			bs = blockSize
			break
		}
	}
	if bs == 0 {
		panic("didn't detect block size")
	}

	buildDict := func(known []byte) map[string]byte {
		dict := make(map[string]byte)

		msg := bytes.Repeat([]byte{42}, bs)
		msg = append(msg, known...)
		msg = append(msg, '?')
		msg = msg[len(msg)-bs:]

		for b := 0; b < 256; b++ {
			msg[bs-1] = byte(b)
			res := string(oracle(msg)[:bs])
			dict[res] = byte(b)
		}
		return dict
	}

	var plaintext []byte
	for i := 0; i < len(oracle([]byte{})); i++ {
		dict := buildDict(plaintext)
		msg := bytes.Repeat([]byte{42}, mod(bs-i-1, bs))
		skip := i / bs * bs
		res := string(oracle(msg)[skip : skip+bs])
		plaintext = append(plaintext, dict[res])

		fmt.Printf("%c", dict[res])
	}
	fmt.Printf("\n")

	return nil
}

func mod(a, b int) int {
	return (a%b + b) % b
}

func profileFor(email string) string {
	profile := url.Values{}
	profile.Add("email", email)
	profile.Add("role", "user")
	profile.Add("uid", strconv.Itoa(10+mathrand.Intn(90)))

	return profile.Encode()
}

func newCutAndPasteECBOracles() (
	generateCookie func(email string) string,
	amIAdmin func(cookie string) bool,
) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		panic("Failed to read from rand")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		panic("Failed to create new AES cypher")
	}

	generateCookie = func(email string) string {
		profile := []byte(profileFor(email))
		cookie := encryptECB(padPKCS7(profile, 16), b)
		return string(cookie)
	}
	amIAdmin = func(cookie string) bool {
		cookie = string(unpadPKCS7(decryptECB([]byte(cookie), b)))
		v, err := url.ParseQuery(cookie)
		if err != nil {
			return false
		}
		return v.Get("role") == "admin"
	}
	return
}

func unpadPKCS7(in []byte) []byte {
	if len(in) == 0 {
		return in
	}
	b := in[len(in)-1]
	if int(b) > len(in) || b == 0 {
		return nil
	}
	for i := 1; i < int(b); i++ {
		if in[len(in)-1-i] != b {
			return nil
		}
	}
	return in[:len(in)-int(b)]
}

func makeECBAdminCookie(generateCookie func(email string) string) string {
	// These could be obtained with recoverECBSuffix
	start, _ := "email=", "&role=user&uid=51"

	genBlock := func(prefix string) string {
		msg := strings.Repeat("A", 16-len(start)) + prefix
		return generateCookie(msg)[16:32]
	}

	block1 := generateCookie("FOO@BAR.AA")[:16] // email=FOO@BAR.AA
	block2 := genBlock("AAAAAAAAAA")            // AAAAAAAAAA&role=
	block3 := genBlock("admin")                 // admin&role=user&
	msg := strings.Repeat("A", 16-1-len(start))
	block4 := generateCookie(msg)[16:48] // role=user&uid=51 + padding

	// email=FOO@BAR.AAAAAAAAAAAA&role=admin&role=user&role=user&uid=51 + padding
	return block1 + block2 + block3 + block4
}
