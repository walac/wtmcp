package vault

import (
	"bytes"
	"strings"
	"testing"
)

func TestIsAnsibleVault(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"vault 1.1", []byte("$ANSIBLE_VAULT;1.1;AES256\n..."), true},
		{"vault 1.2", []byte("$ANSIBLE_VAULT;1.2;AES256;prod\n..."), true},
		{"plaintext", []byte("KEY=value\n"), false},
		{"empty", []byte{}, false},
		{"partial magic", []byte("$ANSIBLE_V"), false},
		{"binary", []byte{0x00, 0x01, 0x02}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAnsibleVault(tt.data); got != tt.want {
				t.Errorf("IsAnsibleVault() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    Header
		wantErr string
	}{
		{
			name:   "vault 1.1",
			header: "$ANSIBLE_VAULT;1.1;AES256",
			want:   Header{Version: "1.1", Cipher: "AES256", VaultID: ""},
		},
		{
			name:   "vault 1.2 with label",
			header: "$ANSIBLE_VAULT;1.2;AES256;prod",
			want:   Header{Version: "1.2", Cipher: "AES256", VaultID: "prod"},
		},
		{
			name:   "vault 1.2 with dash-underscore label",
			header: "$ANSIBLE_VAULT;1.2;AES256;my-vault_id",
			want:   Header{Version: "1.2", Cipher: "AES256", VaultID: "my-vault_id"},
		},
		{
			name:   "vault 1.2 without label",
			header: "$ANSIBLE_VAULT;1.2;AES256",
			want:   Header{Version: "1.2", Cipher: "AES256", VaultID: ""},
		},
		{
			name:   "trailing newline stripped",
			header: "$ANSIBLE_VAULT;1.1;AES256\n",
			want:   Header{Version: "1.1", Cipher: "AES256", VaultID: ""},
		},
		{
			name:   "trailing crlf stripped",
			header: "$ANSIBLE_VAULT;1.1;AES256\r\n",
			want:   Header{Version: "1.1", Cipher: "AES256", VaultID: ""},
		},
		{
			name:    "unsupported version",
			header:  "$ANSIBLE_VAULT;1.3;AES256",
			wantErr: "unsupported vault format: 1.3",
		},
		{
			name:    "unsupported cipher",
			header:  "$ANSIBLE_VAULT;1.1;AES128",
			wantErr: "unsupported vault cipher: AES128",
		},
		{
			name:    "missing prefix",
			header:  "NOT_VAULT;1.1;AES256",
			wantErr: "missing $ANSIBLE_VAULT prefix",
		},
		{
			name:    "too few fields",
			header:  "$ANSIBLE_VAULT;1.1",
			wantErr: "expected 3-4 fields",
		},
		{
			name:    "too many fields",
			header:  "$ANSIBLE_VAULT;1.2;AES256;prod;extra",
			wantErr: "expected 3-4 fields",
		},
		{
			name:    "empty vault ID",
			header:  "$ANSIBLE_VAULT;1.2;AES256;",
			wantErr: "empty vault ID label",
		},
		{
			name:    "invalid vault ID chars",
			header:  "$ANSIBLE_VAULT;1.2;AES256;../../etc",
			wantErr: "invalid vault ID label",
		},
		{
			name:    "vault ID with spaces",
			header:  "$ANSIBLE_VAULT;1.2;AES256;my label",
			wantErr: "invalid vault ID label",
		},
		{
			name:    "vault ID too long",
			header:  "$ANSIBLE_VAULT;1.2;AES256;" + strings.Repeat("a", 65),
			wantErr: "vault ID label too long",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHeader(tt.header)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	password := []byte("test-password-for-round-trip")
	plaintext := []byte("JIRA_URL=https://jira.example.com\nJIRA_TOKEN=secret123\n")

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if !IsAnsibleVault(encrypted) {
		t.Fatal("encrypted data does not have vault header")
	}

	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch:\ngot:  %q\nwant: %q", decrypted, plaintext)
	}
}

func TestRoundTripWithID(t *testing.T) {
	password := []byte("test-password-for-vault-id")
	plaintext := []byte("SECRET=value\n")

	encrypted, err := EncryptWithID(plaintext, password, "prod")
	if err != nil {
		t.Fatalf("EncryptWithID: %v", err)
	}

	if !strings.HasPrefix(string(encrypted), "$ANSIBLE_VAULT;1.2;AES256;prod\n") {
		t.Fatalf("unexpected header: %s", strings.SplitN(string(encrypted), "\n", 2)[0])
	}

	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch:\ngot:  %q\nwant: %q", decrypted, plaintext)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	password := []byte("correct-password")
	plaintext := []byte("SECRET=value\n")

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(encrypted, []byte("wrong-password"))
	if err == nil {
		t.Fatal("expected HMAC error, got nil")
	}
	if !strings.Contains(err.Error(), "HMAC verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptEmptyPlaintext(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("")

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %q", decrypted)
	}
}

func TestEncryptSaltDiffers(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("SECRET=value\n")

	enc1, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("first Encrypt: %v", err)
	}

	enc2, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("second Encrypt: %v", err)
	}

	if bytes.Equal(enc1, enc2) {
		t.Error("two encryptions with the same input produced identical output (salt should differ)")
	}

	dec1, err := Decrypt(enc1, password)
	if err != nil {
		t.Fatalf("Decrypt enc1: %v", err)
	}
	dec2, err := Decrypt(enc2, password)
	if err != nil {
		t.Fatalf("Decrypt enc2: %v", err)
	}
	if !bytes.Equal(dec1, dec2) {
		t.Error("decrypted outputs differ")
	}
}

func TestDecryptTruncatedFile(t *testing.T) {
	_, err := Decrypt([]byte("$ANSIBLE_VAULT;1.1;AES256\n"), nil)
	if err == nil {
		t.Fatal("expected error for truncated file")
	}
}

func TestDecryptCorruptedHex(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("SECRET=value\n")

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	lines := strings.SplitN(string(encrypted), "\n", 2)
	corrupted := lines[0] + "\nZZZZnotvalidhex\n"

	_, err = Decrypt([]byte(corrupted), password)
	if err == nil {
		t.Fatal("expected error for corrupted hex")
	}
	if !strings.Contains(err.Error(), "invalid vault file format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptFileTooLarge(t *testing.T) {
	data := make([]byte, maxFileSize+1)
	copy(data, []byte("$ANSIBLE_VAULT;1.1;AES256\n"))
	_, err := Decrypt(data, []byte("password"))
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncryptWithIDValidation(t *testing.T) {
	password := []byte("test")
	data := []byte("test")

	_, err := EncryptWithID(data, password, "")
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("expected empty vault ID error, got: %v", err)
	}

	_, err = EncryptWithID(data, password, "../../etc")
	if err == nil || !strings.Contains(err.Error(), "invalid vault ID label") {
		t.Errorf("expected invalid vault ID error, got: %v", err)
	}

	_, err = EncryptWithID(data, password, strings.Repeat("x", 65))
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected too long error, got: %v", err)
	}
}

func TestPKCS7(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		padded  int
		wantErr bool
	}{
		{"1 byte", []byte{0x01}, 16, false},
		{"15 bytes", bytes.Repeat([]byte{0xAA}, 15), 16, false},
		{"16 bytes", bytes.Repeat([]byte{0xBB}, 16), 32, false},
		{"17 bytes", bytes.Repeat([]byte{0xCC}, 17), 32, false},
		{"empty", []byte{}, 16, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7Pad(tt.input, 16)
			if len(padded) != tt.padded {
				t.Errorf("padded length = %d, want %d", len(padded), tt.padded)
			}
			if len(padded)%16 != 0 {
				t.Errorf("padded length %d is not a multiple of 16", len(padded))
			}

			unpadded, err := pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("unpad error: %v", err)
			}
			if !bytes.Equal(unpadded, tt.input) {
				t.Errorf("round-trip failed:\ngot:  %x\nwant: %x", unpadded, tt.input)
			}
		})
	}
}

func TestPKCS7UnpadInvalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"zero padding", []byte{0x00}},
		{"padding too large", []byte{0x11}},
		{"inconsistent padding", []byte{0xAA, 0xAA, 0x03, 0x02}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pkcs7Unpad(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte("sensitive-data-here")
	ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d is %d, expected 0", i, b)
		}
	}
}

func TestDecryptNotVaultFile(t *testing.T) {
	_, err := Decrypt([]byte("KEY=value\nTOKEN=secret\n"), []byte("password"))
	if err == nil {
		t.Fatal("expected error for non-vault file")
	}
}

// Interop test vectors generated by ansible-vault 2.20.5 (ansible-core).
// Password: "test-vault-password"

const interopVault11 = `$ANSIBLE_VAULT;1.1;AES256
33643236663766643338386665393630663631366563623461303866383537306536303666373136
3331393461356135353131643765656534656638326432620a313862333433376163343232313537
65363563363263373833623537393431383731366134626534643865333631343762363261373733
6262316432313338340a643635646363626264386262616438316638363264373835316161333935
39386264363565663762663862343339646639616331386432663639366333343462653035663530
30353333626238346365376434316634633238383863343032656563353531613437643039386537
66373731356561393338636532303861613964343662313235353764666534396130366438366362
66303233623632393736383266323137393165386463656638333964383139613738396631386435
3030
`

const interopVault12 = `$ANSIBLE_VAULT;1.2;AES256;prod
35373039323536666439343765653932636433663731316433333738396330303337633135323633
6639333464356638313261366261373462666237306362340a306438613962373930633139633766
36393631373631383261316136326133313030356462653631303330326163336138353631366262
6236333666356437370a316431363734396332356366653237386330303735343366646635613861
36393939663461656238343934376235383232316163333836346564643761613733
`

const interopPassword = "test-vault-password"

const interopPlaintext11 = "JIRA_URL=https://jira.example.com\nJIRA_TOKEN=supersecrettoken123\nJIRA_EMAIL=user@example.com\n"

const interopPlaintext12 = "SECRET=vault-id-test-value\n"

func TestDecryptInteropVault11(t *testing.T) {
	decrypted, err := Decrypt([]byte(interopVault11), []byte(interopPassword))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decrypted) != interopPlaintext11 {
		t.Errorf("decrypted content mismatch:\ngot:  %q\nwant: %q", string(decrypted), interopPlaintext11)
	}
}

func TestDecryptInteropVault12(t *testing.T) {
	decrypted, err := Decrypt([]byte(interopVault12), []byte(interopPassword))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decrypted) != interopPlaintext12 {
		t.Errorf("decrypted content mismatch:\ngot:  %q\nwant: %q", string(decrypted), interopPlaintext12)
	}
}

func TestDecryptInteropVault12Header(t *testing.T) {
	header, err := ParseHeader("$ANSIBLE_VAULT;1.2;AES256;prod")
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if header.VaultID != "prod" {
		t.Errorf("VaultID = %q, want %q", header.VaultID, "prod")
	}
}

func TestDecryptInteropWrongPassword(t *testing.T) {
	_, err := Decrypt([]byte(interopVault11), []byte("wrong-password"))
	if err == nil {
		t.Fatal("expected HMAC error with wrong password on real ansible-vault data")
	}
	if !strings.Contains(err.Error(), "HMAC verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptBitFlipTamperDetection(t *testing.T) {
	password := []byte("tamper-test-password")
	plaintext := []byte("SECRET=tamper-test-value\n")

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a single bit in the hex body (not the header).
	data := []byte(string(encrypted))
	for i := len("$ANSIBLE_VAULT;1.1;AES256\n") + 10; i < len(data); i++ {
		if data[i] != '\n' {
			data[i] ^= 0x01
			break
		}
	}

	_, err = Decrypt(data, password)
	if err == nil {
		t.Fatal("expected error after bit-flip tamper, got nil")
	}
}

func TestParseHeaderRejectsVaultIDOn11(t *testing.T) {
	_, err := ParseHeader("$ANSIBLE_VAULT;1.1;AES256;sneaky")
	if err == nil {
		t.Fatal("expected error for vault ID on 1.1 header")
	}
	if !strings.Contains(err.Error(), "vault 1.1 header must not have a vault ID label") {
		t.Fatalf("unexpected error: %v", err)
	}
}
