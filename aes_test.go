package aesecb

import (
	"testing"
)

type PlantTextAndCiphertext struct {
	PlantText  string
	Ciphertext string
}

var cases = []PlantTextAndCiphertext{
	PlantTextAndCiphertext{"1457490591/0C:C6:55:FD:48:FB/000000000000000/sn/zzz",
		"9B1F1600E65AA58C24C2B6BAC175513491EB0EE0D744AD9171D1615E434610AEE46CDA6EA3CC54D6FDC9C3CDF7BEA2587D8205A69F5655C77C2A1C9A6D5C026A"},
	PlantTextAndCiphertext{"1457490591/0C:C6:55:FD:48:FB/000000000000000/sn/",
		"9B1F1600E65AA58C24C2B6BAC175513491EB0EE0D744AD9171D1615E434610AEE46CDA6EA3CC54D6FDC9C3CDF7BEA258"},
}

var key = "1234567890abcdef"

func TestEncryptString(t *testing.T) {
	for _, v := range cases {
		ret, err := EncryptString(v.PlantText, key)

		if err != nil {
			t.Fatalf("EncryptString(`%s`) error: `%s`", v.PlantText, err)

		}

		if ret != v.Ciphertext {
			t.Fatalf("EncryptString(`%s`) want `%s` not `%s`", v.PlantText, v.Ciphertext, ret)
		}
	}
}

func TestDecryptString(t *testing.T) {
	for _, v := range cases {
		ret, err := DecryptString(v.Ciphertext, key)

		if err != nil {
			t.Fatalf("DecryptString(`%s`) error: `%s`", v.Ciphertext, err)

		}

		if ret != v.PlantText {
			t.Fatalf("DecryptString(`%s`) want `%s` not `%s`", v.Ciphertext, v.PlantText, ret)
		}
	}
}
