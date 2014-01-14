// Open Jaeger DB file and Add/Delete/Change/View values
// Most important is Add and Change. These require public key handling
// The other code exists
// e.g.
// echo -n "Test base64 GPG public key encrypted string" | gpg -er 7F98BBCE | base64
//
// Read recipient from public key ring
// ~/.gnupg/pubring.gpg

package main

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
)

const jaegerJSONGPGDBExtension = ".jgrdb"
const jaegerQuote = "Stacker Pentecost: Haven't you heard Mr. Beckett? The world is coming to an end. So where would you rather die? Here? Or in a Jaeger!"

var debug debugging = false // or flip to false

type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	// From: https://groups.google.com/forum/#!msg/golang-nuts/gU7oQGoCkmg/BNIl-TqB-4wJ
	if d {
		log.Printf(format, args...)
	}
}

type Data struct {
	Properties []Property
}

type Property struct {
	Name           string `json:"Name"`
	EncryptedValue string `json:"EncryptedValue"`
}

func main() {
	// Define flags
	var (
		addKey      = flag.String("a", "", "Add property")
		debugFlag   = flag.Bool("d", false, "Enable Debug")
		deleteKey   = flag.String("delete", "", "Delete property")
		jsonGPGDB   = flag.String("j", "", "JSON GPG database file. eg. file.txt.jgrdb")
		keyringFile = flag.String("k", "", "Keyring file. Public key in armor format. eg. pubring.asc")
		value       = flag.String("v", "", "Value for keys to use")
	)
	// Parse
	// Any additional non-flag arguments can be retrieved with flag.Args() which returns a []string.
	flag.Parse()

	if *debugFlag {
		debug = true
	}

	if *jsonGPGDB == "" {
		flag.Usage()
		log.Fatalf("\n\nError: No JSON GPG database file specified")
		return
	}

	if *deleteKey != "" {
		deleteKeyJaegerDB(deleteKey, jsonGPGDB)
	}

	var entity *openpgp.Entity
	var entitylist openpgp.EntityList

	if *keyringFile == "" {
		entity, entitylist = processPublicKeyRing()
	} else {
		entity, entitylist = processArmoredKeyRingFile(keyringFile)
	}

	if *addKey != "" {
		addKeyJaegerDB(addKey, value, jsonGPGDB)
	}

	fmt.Println("Hello World!", *jsonGPGDB, *keyringFile, entity, entitylist)
}

func encodeBase64EncryptedMessage(s string, keyring openpgp.KeyRing) string {
	// Encrypt message using public key and then encode with base64
	debug.Printf("keyring: #%v", keyring)
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, keyring, nil, nil, nil)
	if err != nil {
		log.Fatalln("ERR: Error encrypting message - ", err)
	}

	_, err = w.Write([]byte(s))
	if err != nil {
	}
	err = w.Close()
	if err != nil {
	}

	// Output as base64 encoded string
	bytes, err := ioutil.ReadAll(buf)
	str := base64.StdEncoding.EncodeToString(bytes)

	fmt.Println("Public key encrypted message (base64 encoded):", str)

	return str
}

func processPublicKeyRing() (entity *openpgp.Entity, entitylist openpgp.EntityList) {
	// TODO: Handle a specified recipient
	// Get default public keyring location
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	jaegerPublicKeyRing := fmt.Sprintf("%v/.gnupg/jaeger_pubring.gpg", usr.HomeDir)
	publicKeyRing := ""

	if _, err := os.Stat(jaegerPublicKeyRing); err == nil {
		publicKeyRing = jaegerPublicKeyRing
	} else {
		publicKeyRing = fmt.Sprintf("%v/.gnupg/pubring.gpg", usr.HomeDir)
	}

	debug.Printf("publicKeyRing file:", publicKeyRing)
	publicKeyRingBuffer, err := os.Open(publicKeyRing)
	if err != nil {
		panic(err)
	}
	entitylist, err = openpgp.ReadKeyRing(publicKeyRingBuffer)
	if err != nil {
		log.Fatal(err)
	}

	entity = entitylist[0]
	debug.Printf("Public key default keyring:", entity.Identities)

	return entity, entitylist
}

func processArmoredKeyRingFile(keyringFile *string) (entity *openpgp.Entity, entitylist openpgp.EntityList) {
	keyringFileBuffer, err := os.Open(*keyringFile)
	if err != nil {
		log.Fatalln("ERROR: Unable to read keyring file")
	}
	entitylist, err = openpgp.ReadArmoredKeyRing(keyringFileBuffer)
	if err != nil {
		log.Fatal(err)
	}
	entity = entitylist[0]
	debug.Printf("Public key from armored string:", entity.Identities)

	return entity, entitylist
}

func addKeyJaegerDB(key *string, value *string, jsonGPGDB *string) {
	fmt.Println(key, value, jsonGPGDB)
}

func deleteKeyJaegerDB(key *string, jsonGPGDB *string) {
	debug.Printf("deleteKeyJaegerDB key: %v", *key)

	// json handling
	jsonGPGDBBuffer, err := ioutil.ReadFile(*jsonGPGDB)
	if err != nil {
		log.Fatalln("ERROR: Unable to read JSON GPG DB file")
	}

	var j Data
	if err := json.Unmarshal(jsonGPGDBBuffer, &j); err != nil {
		panic(err)
	}
	debug.Printf("json unmarshal: %v", j)

	var newP []Property
	found := false

	for i, _ := range j.Properties {
		property := &j.Properties[i]
		debug.Printf("i: %v, Name: %#v, EncryptedValue: %#v\n", i, property.Name, property.EncryptedValue)
		if property.Name == *key {
			// https://code.google.com/p/go-wiki/wiki/SliceTricks
			newP = j.Properties[:i+copy(j.Properties[i:], j.Properties[i+1:])]
			found = true
			break
		}
	}

	if !found {
		log.Fatalf("\n\nError: Property '%s' not found.", *key)
	}

	debug.Printf("new properties: %v", newP)

	newData := Data{newP}

	bytes, err := json.MarshalIndent(newData, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}

	debug.Printf("b: %v", string(bytes))

	// Writing file
	// To handle large files, use a file buffer: http://stackoverflow.com/a/9739903/603745
	if err := ioutil.WriteFile(*jsonGPGDB, bytes, 0644); err != nil {
		panic(err)
	} else {
		log.Fatalln("Wrote file:", *jsonGPGDB)
	}

}
