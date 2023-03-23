package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
)

type NMapRun struct {
	XMLName  xml.Name `xml:"nmaprun"`
	HostList []Host   `xml:"host"`
	Stats    RunStats `xml:"runstats"`
}
type Host struct {
	XMLName   xml.Name  `xml:"host"`
	Addresses []Address `xml:"address"`
	Status    Status    `xml:"status"`
	Ports     Ports     `xml:"ports"`
}
type Address struct {
	XMLName  xml.Name `xml:"address"`
	Addr     string   `xml:"addr,attr"`
	AddrType string   `xml:"addrtype,attr"`
	Vendor   string   `xml:"vendor,attr"`
}
type Status struct {
	XMLName   xml.Name `xml:"status"`
	State     string   `xml:"state,attr"`
	Reason    string   `xml:"reason,attr"`
	ReasonTTL string   `xml:"reason_ttl,attr"`
}
type RunStats struct {
	XMLName  xml.Name `xml:"runstats"`
	Finished Finished `xml:"finished"`
	Hosts    Hosts    `xml:"hosts"`
}
type Finished struct {
	XMLName xml.Name `xml:"finished"`
	Time    string   `xml:"timestr,attr"`
	Summary string   `xml:"summary,attr"`
	Elapsed string   `xml:"elapsed,attr"`
	Exit    string   `xml:"exit,attr"`
}
type Hosts struct {
	XMLName xml.Name `xml:"hosts"`
	Up      string   `xml:"up,attr"`
	Down    string   `xml:"down,attr"`
	Total   string   `xml:"total,attr"`
}
type Ports struct {
	XMLName  xml.Name  `xml:"ports"`
	Ports    []Port    `xml:"port"`
	States   []State   `xml:"state"`
	Services []Service `xml:"service"`
}
type Port struct {
	XMLName  xml.Name `xml:"port"`
	Protocol string   `xml:"protocol,attr"`
	Port     string   `xml:"portid,attr"`
}
type State struct {
	XMLName xml.Name `xml:"state"`
	State   string   `xml:"state,attr"`
	Reason  string   `xml:"reason,attr"`
}
type Service struct {
	XMLName xml.Name `xml:"service"`
	Name    string   `xml:"name,attr"`
	Method  string   `xml:"method,attr"`
	Conf    string   `xml:"conf,attr"`
}

func readLANScan() NMapRun {
	xmlFile, err := os.Open("localNetwork.xml")
	if err != nil {
		fmt.Println(err.Error())
	}
	defer xmlFile.Close()

	byteVal, err := ioutil.ReadAll(xmlFile)
	if err != nil {
		fmt.Println(err.Error())
	}
	var run NMapRun
	err = xml.Unmarshal(byteVal, &run)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("Run: " + run.Stats.Hosts.Up)
	//Remove duplicate entries
	for i := 0; i < len(run.HostList); i++ {
		if len(run.HostList[i].Ports.Ports) < 1 {
			run.HostList = append(run.HostList[:i], run.HostList[i+1:]...)
			i--
		}
	}
	return run
}
