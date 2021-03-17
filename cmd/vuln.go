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

var pkgName string

// VulnRecord is the struct containing values within a vulnerability record
type VulnRecord struct {
	CveTitle string   `json:"csv_title"`
	Severity string   `json:"severity"`
	Solution string   `json:"solution"`
	Count    int      `json:"count"`
	IPList   []string `json:"ip_list"`
}

// CheckIfIPExist checks if ip exists in a slice
func CheckIfIPExist(ip string, IPList []string) bool {
	for _, value := range IPList {
		if value == ip {
			return true
		}
	}
	return false
}

// PrsRrdVuln parses each record in csv and updates the slice of vulnerabilities
func PrsRrdVuln(vulnDict map[string]VulnRecord, record []string, severityMap map[string]string) {
	packages := ParsePackage(record[31])

	for _, pkg := range packages {
		_, valueInDict := vulnDict[pkg]
		if !valueInDict {
			vulnDict[pkg] = VulnRecord{
				CveTitle: record[8],
				Severity: severityMap[record[11]],
				Solution: record[28],
				Count:    1,
				IPList:   []string{record[0]},
			}
		}

		// Check if the ip is in the list of ips belonging to the vuln record
		if !CheckIfIPExist(record[0], vulnDict[pkg].IPList) {
			newIPList := append(vulnDict[pkg].IPList, record[0])
			newCount := vulnDict[pkg].Count + 1

			vulnDict[pkg] = VulnRecord{
				CveTitle: vulnDict[pkg].CveTitle,
				Severity: vulnDict[pkg].Severity,
				Solution: vulnDict[pkg].Solution,
				Count:    newCount,
				IPList:   newIPList,
			}
		}
	}
}

// GetVulnDictKeys transforms dictionary to an array containing vulnerabilities
func GetVulnDictKeys(vulnDict map[string]VulnRecord) []string {
	vulnList := []string{}
	for vuln := range vulnDict {
		vulnList = append(vulnList, vuln)
	}
	return vulnList
}

// WriteVulnMapToFile write to json file given a map
func WriteVulnMapToFile(fileName string, ipDict map[string]VulnRecord) {
	jsonString, _ := json.Marshal(ipDict)
	_ = ioutil.WriteFile(fileName, jsonString, os.ModePerm)
}

// GetVulnerabilities parses input report
func GetVulnerabilities() {
	vulnDict := make(map[string]VulnRecord)
	severityMap := map[string]string{
		"1": "Low",
		"2": "Low",
		"3": "Medium",
		"4": "High",
		"5": "High",
	}

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
			PrsRrdVuln(vulnDict, record, severityMap)
		}
	}

	if pkgName == "" {
		// Generates just a list of IPs
		if listOnly {
			vulnDictKeys := GetVulnDictKeys(vulnDict)
			fmt.Printf("The vulnerable packages found :\n")
			fmt.Println(strings.Join(vulnDictKeys, "\n"))
			fmt.Printf("There are a total of %d of package(s) found\n", len(vulnDictKeys))
		} else {
			WriteVulnMapToFile(outputFileName, vulnDict)
		}

	} else {
		_, valueInDict := vulnDict[pkgName]
		if len(vulnDict[pkgName].IPList) == 0 || !valueInDict {
			fmt.Printf("The ip(s) for the package %s cannot be found!\n", pkgName)
		} else {
			fmt.Printf("The ip(s) found for the package %s are:\n", pkgName)
			fmt.Println(strings.Join(vulnDict[pkgName].IPList, "\n"))
		}
	}
}
