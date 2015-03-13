package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

const jaegerTemplateExtension = ".jgrt"
const jaegerDescription = "JaegerH - Jaeger Helper program\n\nJaeger is a JSON encoded GPG encrypted key value store. It is useful for separating development with operations and keeping configuration files secure."
const jaegerQuote = "\"Stacker Pentecost: Haven't you heard Mr. Beckett? The world is coming to an end. So where would you rather die? Here? Or in a Jaeger!\" - Pacific Rim"
const jaegerRecommendedUsage = "RECOMMENDED:\n    jaegerh -i file.txt.jgrt"

var debug debugging = false

type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	// From: https://groups.google.com/forum/#!msg/golang-nuts/gU7oQGoCkmg/BNIl-TqB-4wJ
	if d {
		log.Printf(format, args...)
	}
}

func main() {
	// Define flags
	var (
		debugFlag     = flag.Bool("d", false, "Enable Debug")
		inputTemplate = flag.String("i", "", "Input Template file. eg. file.txt.jgrt")
	)

	flag.Usage = func() {
		fmt.Printf("%s\n%s\n\n%s\n\n", jaegerDescription, jaegerQuote, jaegerRecommendedUsage)
		fmt.Fprintf(os.Stderr, "OPTIONS:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *debugFlag {
		debug = true
	}

	if *inputTemplate == "" {
		flag.Usage()
		log.Fatalf("\n\nError: No input template file specified")
	}

	processInputFile(inputTemplate)
}

func processInputFile(inputFile *string) {
	file, err := os.Open(*inputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		matched, _ := regexp.MatchString(".*=.*", scanner.Text())
		if matched {
			parseLine(scanner.Text())
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func parseLine(line string) {
	s := regexp.MustCompile("=").Split(line, 2)
	key := camelKey(strings.TrimSpace(s[0]))
	value := strings.TrimSpace(s[1])
	if value != "" {
		fmt.Printf("jaegerdb -a %s -v '%s'\n", key, value)
	}
}

func camelKey(src string) string {
	// From: https://github.com/etgryphon/stringUp

	var camelingRegex = regexp.MustCompile("[0-9A-Za-z]+")

	byteSrc := []byte(src)
	chunks := camelingRegex.FindAll(byteSrc, -1)
	for idx, val := range chunks {
		chunks[idx] = bytes.Title(val)
	}
	return string(bytes.Join(chunks, nil))
}
