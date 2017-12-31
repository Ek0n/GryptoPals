package GryptoPals

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestProblem9(t *testing.T) {
	if res := padPKCS7([]byte("YELLOW SUBMARINE"), 16); !bytes.Equal(res, []byte("YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")) {
		t.Errorf("%q", res)
	}
	if res := padPKCS7([]byte("YELLOW SUBMARINE"), 20); !bytes.Equal(res, []byte("YELLOW SUBMARINE\x04\x04\x04\x04")) {
		t.Errorf("%q", res)
	}
}

func TestProblem10(t *testing.T) {
	msg := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	iv := make([]byte, 16)
	b, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	res := decryptCBC(encryptCBC(msg, b, iv), b, iv)
	if !bytes.Equal(res, msg) {
		t.Errorf("%q", res)
	}

	msg = decodeBase64(t, string(readFile(t, "10.txt")))
	t.Logf("%s", decryptCBC(msg, b, iv))
}

func TestProblem11(t *testing.T) {
	oracle := newECBCBCOracle()
	payload := bytes.Repeat([]byte{42}, 16*3)
	ecb, cbc := 0, 0
	for i := 0; i < 1000; i++ {
		out := oracle(payload)
		if detectECB(out, 16) {
			ecb++
		} else {
			cbc++
		}
	}
	t.Log(ecb, cbc)
}

func TestProblem12(t *testing.T) {
	secret := decodeBase64(t,
		`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)
	oracle := newECBSuffixOracle(secret)
	recoverECBSuffx(oracle)
}
