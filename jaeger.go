// Stacker Pentecost: Haven't you heard Mr. Beckett? The world is coming to an end.
// So where would you rather die? Here? Or in a Jaeger!

package main

import (
	"flag"
	"fmt"

	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const jaegerTemplateExtension = ".jgrt"
const jaegerJSONGPGDBExtension = ".jgrdb"

func decryptBase64EncryptedMessage(s string, keyring openpgp.KeyRing) {
	// Decrypt base64 encoded encrypted message using decrypted private key
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), keyring, nil /* no prompt */, nil)
	if err != nil {
		fmt.Println("error reading message", err)
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	fmt.Println("md:", string(bytes))
}

func main() {
	// Define flags
	var (
		inputTemplate     = flag.String("i", "", "Input Template file. eg. file.txt.jgrt")
		jsonGPGDB         = flag.String("j", "", "JSON GPG database file. eg. file.txt.jgrdb")
		outputFile        = flag.String("o", "", "Output file. eg. file.txt")
		keyringFile       = flag.String("k", "", "Keyring file. Secret key in armor format. eg. secret.asc")
		passphraseKeyring = flag.String("p", "", "Passphrase for keyring. If this is not set the passphrase will be blank of read from the environment variable PASSPHRASE.")
	)
	// Parse
	// Any additional non-flag arguments can be retrieved with flag.Args() which returns a []string.
	flag.Parse()

	if *inputTemplate == "" {
		flag.Usage()
		log.Fatalf("\n\nError: No input file specified")
		return
	}

	// TODO: Handle reading from default keyring
	if *keyringFile == "" {
		flag.Usage()
		log.Fatalf("\n\nError: No keyring file specified")
		return
	}

	basefilename := ""

	if strings.HasSuffix(*inputTemplate, jaegerTemplateExtension) {
		basefilename = strings.TrimSuffix(*inputTemplate, jaegerTemplateExtension)
	}

	if *jsonGPGDB == "" {
		if basefilename == "" {
			flag.Usage()
			log.Fatalf("\n\nERROR: No JSON GPG DB file specified or input file does not have a %v extension", jaegerTemplateExtension)
			return
		}
		// Set from the basefilename
		*jsonGPGDB = fmt.Sprintf("%v%v", basefilename, jaegerJSONGPGDBExtension)
	}

	if *outputFile == "" {
		if basefilename == "" {
			flag.Usage()
			log.Fatalf("\n\nERROR: No Output file specified or input file does not have a %v extension", jaegerTemplateExtension)
			return
		}
		// Set from the basefilename
		*outputFile = basefilename

	}

	if *passphraseKeyring == "" {
		passphrase := os.Getenv("PASSPHRASE")
		if len(passphrase) != 0 {
			*passphraseKeyring = passphrase
		}
	}

	fmt.Println("basefilename:", basefilename)
	fmt.Println("jsonGPGDB:", *jsonGPGDB)
	fmt.Println("outputFile:", *outputFile)
	fmt.Println("passphrase:", *passphraseKeyring)
	fmt.Println(*jsonGPGDB, *outputFile, *keyringFile)

	// Read armored private key into type EntityList
	// An EntityList contains one or more Entities.
	// This assumes there is only one Entity involved
	// TODO: Read default keyring
	// TODO: Support to prompt for passphrase
	//entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(privateKey))
	keyringFileBuffer, err := os.Open(*keyringFile)
	if err != nil {
		log.Fatalln("ERROR: Unable to read keyring file")
	}
	entitylist, err := openpgp.ReadArmoredKeyRing(keyringFileBuffer)
	if err != nil {
		log.Fatal(err)
	}
	entity := entitylist[0]
	fmt.Println("Private key from armored string:", entity.Identities)

	// Decrypt private key using passphrase
	passphrase := []byte(*passphraseKeyring)
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		fmt.Println("Decrypting private key using passphrase")
		err := entity.PrivateKey.Decrypt(passphrase)
		if err != nil {
			log.Fatalln("ERROR: Failed to decrypt key")
		}
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			err := subkey.PrivateKey.Decrypt(passphrase)
			if err != nil {
				log.Fatalln("ERROR: Failed to decrypt subkey")
			}
		}
	}

}
