// license that can be found in the LICENSE file.

// Golang port of https://metacpan.org/pod/Crypt::Juniper
// Original Author: https://metacpan.org/pod/Crypt::Juniper#AUTHOR
// Ported By: nadddy
package jcrypt

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
)

const (
	magic string = "$9$"
)

var decryptError error = errors.New("Invalid encrypted text")
var numAlpha = make([]byte, 0)
var itoa64 []byte = []byte("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

var numAlphaTotalLen int
var extraNum []int = make([]int, 256) //Using array as map
var alphaNum []int = make([]int, 256) //Using array as map
var encoding = [][]int{{1, 4, 32}, {1, 16, 32}, {1, 8, 32}, {1, 64}, {1, 32}, {1, 4, 16, 128}, {1, 32, 64}}

// init initializes dictionary
func init() {
	family := [][]byte{
		[]byte("QzF3n6/9CAtpu0O"),
		[]byte("B1IREhcSyrleKvMW8LXx"),
		[]byte("7N-dVbwsY2g4oaJZGUDj"),
		[]byte("iHkq.mPf5T"),
	}

	offset := 0
	for i, bs := range family {
		numAlpha = append(numAlpha, bs...)
		for j, b := range bs {
			alphaNum[b] = offset + j
			extraNum[b] = 3 - i
		}
		offset += len(bs)
	}
	numAlphaTotalLen = offset
}

// nibble splits cref at index
func nibble(cref []byte, index int) ([]byte, []byte, error) {
	if index > len(cref) {
		return nil, nil, decryptError
	}
	nib := cref[0:index]
	rest := cref[index:]
	return nib, rest, nil
}

func gap(c1, c2 byte) byte {
	g := (alphaNum[c2]-alphaNum[c1])%numAlphaTotalLen - 1
	// Rollover if g is negative
	if g < 0 {
		g += 65
	}
	return byte(g)
}

func gapDecode(gaps []byte, dec []int) byte {
	num := 0
	if len(gaps) != len(dec) {
		fmt.Println("Nibble and decode size not the same!")
	}
	for i := 0; i < len(gaps); i++ {
		num += int(gaps[i]) * dec[i]
	}
	return byte(num % 256)
}

// randomSalt generates random salt strings.
func randomSalt(r *rand.Rand, size int) []byte {
	b := make([]byte, 0)
	for i := 0; i < size; i++ {
		b = append(b, itoa64[rand.Intn(len(itoa64))])
	}
	return b
}

// gpEncode encode plain text character with a series of gaps
func gapEncode(b, prev byte, enc []int) []byte {
	crypt := make([]byte, 0)
	val := int(b)
	gaps := make([]byte, len(enc))

	for i := len(enc); i > 0; i-- {
		gaps[i-1] = byte(val / enc[i-1])
		val %= enc[i-1]
	}

	for _, gap := range gaps {
		gap += byte(alphaNum[prev]) + 1
		prev = numAlpha[int(gap)%numAlphaTotalLen]
		crypt = append(crypt, prev)
	}
	return crypt
}

// encrypt encrypts <plain> in $9$ format
func Encrypt(plain string, seed int64) string {
	// new Random from seed
	r := rand.New(rand.NewSource(seed))
	salt := randomSalt(r, 1)[0]
	rand := randomSalt(r, extraNum[salt])

	prev := salt
	crypt := make([]byte, 0, 256)
	crypt = append(crypt, []byte(magic)...)
	crypt = append(crypt, salt)
	crypt = append(crypt, rand...)

	pb := []byte(plain)

	// Start encoding byte by byte
	for pos, b := range pb {
		encode := encoding[pos%len(encoding)]
		crypt = append(crypt, gapEncode(b, prev, encode)...)
		prev = crypt[len(crypt)-1]
	}

	return string(crypt)
}

// Decrypt decrypts encrypted crypt to plain text.
// Retruns error if crypt is not encrypted by $9$ encryption
func Decrypt(crypt string) (string, error) {
	if !strings.HasPrefix(crypt, magic) {
		return "", decryptError
	}
	var n []byte
	// Remove magic from input
	b := []byte(crypt)[3:]

	first, b, err := nibble(b, 1)
	if err != nil {
		return "", nil
	}
	_, b, err = nibble(b, extraNum[first[0]])
	if err != nil {
		return "", nil
	}
	prev := first[0]
	decrypt := make([]byte, 0)

	// Iterate till b has something
	for len(b) > 0 {
		decode := encoding[len(decrypt)%len(encoding)]
		n, b, err = nibble(b, len(decode))
		if err != nil {
			return "", nil
		}
		gaps := make([]byte, 0)
		for _, nb := range n {
			g := gap(prev, nb)
			prev = nb
			gaps = append(gaps, g)
		}
		decrypt = append(decrypt, gapDecode(gaps, decode))
	}
	return string(decrypt), nil
}
