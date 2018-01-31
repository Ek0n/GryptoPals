package GryptoPals

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestProblem17(t *testing.T) {
	plaintexts := [][]byte{
		decodeBase64(t, "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
		decodeBase64(t, "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
		decodeBase64(t, "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
		decodeBase64(t, "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
		decodeBase64(t, "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
		decodeBase64(t, "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
		decodeBase64(t, "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
		decodeBase64(t, "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
		decodeBase64(t, "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
		decodeBase64(t, "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
	}
	for i, plaintext := range plaintexts {
		encryptMessage, checkMessagePadding := newCBCPaddingOracles(plaintext)
		res := attackCBCPaddingOracle(encryptMessage(), checkMessagePadding)
		t.Logf("%q", res)
		if !bytes.Equal(unpadPKCS7(res), plaintext) {
			t.Errorf("Plaintext %d recovered incorrectly.", i)
		}
	}
}

func TestProblem18(t *testing.T) {
	b, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	nonce := make([]byte, 8)
	msg := decodeBase64(t, "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	res := decryptCTR(msg, b, nonce)
	t.Logf("%q", res)
	if len(res) != len(msg) {
		t.Error("Wrong length.")
	}
}

func TestProblem20(t *testing.T) {
	encryptMessage := newFixedNonceCTROracle()
	var plaintexts, ciphertexts [][]byte
	for _, line := range bytes.Split(readFile(t, "testdata/20.txt"), []byte("\n")) {
		pt := decodeBase64(t, string(line))
		plaintexts = append(plaintexts, pt)
		ciphertexts = append(ciphertexts, encryptMessage(pt))
	}

	keystream := findFixedNonceCTRKeystream(ciphertexts, corpus)

	for i := range plaintexts {
		t.Logf("%d: %q", i, xor(keystream, ciphertexts[i]))
	}
}
