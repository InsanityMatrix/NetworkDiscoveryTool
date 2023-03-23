package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/exp/slices"
)

var blockedTargetIPs []net.IP
var blockedTargetMACs []string

type Firewall struct {
	blockedTargets []net.IP
	allowedTargets []net.IP
}

func (firewall Firewall) blockData(newTargetIP string) {
	//Check if device already blocked
	ip := net.ParseIP(newTargetIP)
	for i := 0; i < len(firewall.blockedTargets); i++ {
		if firewall.blockedTargets[i].Equal(ip) {
			//already blocked so allow it again
			firewall.allowIP(firewall.blockedTargets[i].String())
			firewall.blockedTargets = slices.Delete(firewall.blockedTargets, i, i+1)
			return
		}
	}
	//re-set IPBlocks rule without that ip allowed
	firewall.blockedTargets = append(firewall.blockedTargets, ip)
	firewall.setBlockedRule()
}

func (firewall Firewall) allowIP(newTargetIP string) {
	//Add new target to the allowed Targets
	firewall.allowedTargets = append(firewall.allowedTargets, net.ParseIP(newTargetIP))
	firewall.setAllowedRule()
}

func (firewall Firewall) setAllowedRule() {
	args := "advfirewall firewall show rule name=\"PoisonedTargets\""
	cmd := exec.Command("netsh", strings.Split(args, " ")...)
	output, _ := cmd.Output()
	outputStr := string(output)
	if !strings.Contains(outputStr, "No rules") {
		args = "advfirewall firewall delete rule name=\"PoisonedTargets\""
		cmd = exec.Command("netsh", strings.Split(args, " ")...)
		cmd.Output()
	}
	directions := []string{"in", "out"}
	for _, dir := range directions {
		rule := fmt.Sprintf("advfirewall firewall add rule name=\"PoisonedTargets\" protocol=any dir=%s action=allow remoteip=", dir)
		for index := 0; index < len(firewall.allowedTargets); index++ {
			rule += firewall.allowedTargets[index].String() + ","
		}
		lastCharIndex := len(rule) - 1
		lastChar := rule[lastCharIndex]
		if lastChar == ',' {
			rule = rule[:lastCharIndex]
		}
		cmd := exec.Command("netsh", strings.Split(rule, " ")...)
		_, err := cmd.Output()
		if err != nil {
			fmt.Printf("Error setting rule: %s\n", getRedText(err.Error()))
			return
		}
	}
	fmt.Print("Added Allowed Targets to Firewall")
}

func (firewall Firewall) setBlockedRule() {
	args := "advfirewall firewall show rule name=\"IPBlocks\""
	cmd := exec.Command("netsh", strings.Split(args, " ")...)
	output, _ := cmd.Output()
	outputStr := string(output)
	if !strings.Contains(outputStr, "No rules") {
		args = "advfirewall firewall delete rule name=\"IPBlocks\""
		cmd = exec.Command("netsh", strings.Split(args, " ")...)
		cmd.Output()
	}
	directions := []string{"in", "out"}
	for _, dir := range directions {
		rule := fmt.Sprintf("advfirewall firewall add rule name=\"IPBlocks\" protocol=any dir=%s action=block remoteip=", dir)
		for index := 0; index < len(firewall.blockedTargets); index++ {
			rule += firewall.blockedTargets[index].String() + ","
		}
		lastCharIndex := len(rule) - 1
		lastChar := rule[lastCharIndex]
		if lastChar == ',' {
			rule = rule[:lastCharIndex]
		}
		cmd := exec.Command("netsh", strings.Split(rule, " ")...)
		_, err := cmd.Output()
		if err != nil {
			fmt.Printf("Error setting rule: %s\n", getRedText(err.Error()))
			return
		}
	}
	fmt.Print("Added Blocked Targets to Firewall")
}
