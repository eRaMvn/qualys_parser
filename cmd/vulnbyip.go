package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var inputFileName string
var outputFileName string
var detailSet bool
var hostIP string
var listOnly bool

// PrsRrdVulnByIP parses each record in csv and updates the dictionary
func PrsRrdVulnByIP(ipDict map[string]map[string]bool, ip string, packages *[]string) {
	// Check if value in Dictionary
	_, valueInDict := ipDict[ip]
	if !valueInDict {
		ipDict[ip] = make(map[string]bool)
	}

	for _, pkg := range *packages {
		if !ipDict[ip][pkg] {
			ipDict[ip][pkg] = true
		}
	}
}

// ParsePackage parses the Results field and returns the list of packages
func ParsePackage(recordField string) []string {
	var packages []string
	lines := strings.Split(recordField, "\n")

	for i, line := range lines {
		if i == 0 {
			continue
		}

		lineWords := strings.Fields(line)
		// Ignore blank lines
		if len(lineWords) == 0 {
			continue
		}

		if detailSet {
			packageInfo := fmt.Sprintf("%s | %s | %s", lineWords[0], lineWords[1], lineWords[2])
			packages = append(packages, packageInfo)
		} else {
			packages = append(packages, lineWords[0])
		}
	}

	return packages
}

func convertDict(ipDict map[string]map[string]bool) map[string][]string {
	convertedDict := make(map[string][]string)
	for ip := range ipDict {
		keys := make([]string, len(ipDict[ip]))

		i := 0
		for k := range ipDict[ip] {
			keys[i] = k
			i++
		}
		convertedDict[ip] = keys
	}
	return convertedDict
}

// GetIPDictKeys transforms dictionary to an array containing ips
func GetIPDictKeys(ipDict map[string]map[string]bool) []string {
	ipList := []string{}
	for ip := range ipDict {
		ipList = append(ipList, ip)
	}
	return ipList
}

// WriteIPMapToFile writes to json file given a map
func WriteIPMapToFile(fileName string, ipDict map[string][]string) {
	jsonString, _ := json.Marshal(ipDict)
	_ = ioutil.WriteFile(fileName, jsonString, os.ModePerm)
}

// GetVulnerabilitiesByIP gets the list of vulnerabilities for each ip
func GetVulnerabilitiesByIP() {
	ipDict := make(map[string]map[string]bool)

	f, err := os.Open(inputFileName)

	if err != nil {
		log.Fatal(err)
	}

	r := csv.NewReader(f)

	ipOrder := 0
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}

		if record[0] == "IP" {
			ipOrder++
			continue
		}

		if ipOrder == 2 {
			// 31 is Result field
			packages := ParsePackage(record[31])
			PrsRrdVulnByIP(ipDict, record[0], &packages)
		}
	}

	convertedDict := convertDict(ipDict)
	if hostIP == "" {
		if listOnly {
			ipDictKeys := GetIPDictKeys(ipDict)
			fmt.Printf("The IPs with vulnerable packages:\n")
			fmt.Println(strings.Join(ipDictKeys, "\n"))
			fmt.Printf("There are a total of %d of ip(s) found\n", len(ipDictKeys))
		} else {
			WriteIPMapToFile(outputFileName, convertedDict)
		}
	} else {
		if len(convertedDict[hostIP]) == 0 {
			fmt.Printf("The vulnerable package(s) found for the host %s cannot be found!\n", hostIP)
		} else {
			fmt.Printf("The vulnerable package(s) found for the host %s are:\n", hostIP)
			fmt.Println(strings.Join(convertedDict[hostIP], "\n"))
		}
	}
}
