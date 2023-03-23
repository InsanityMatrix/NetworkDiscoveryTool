package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

//Global Data
var wifiInterface string
var lastLocalScan string
var localIP string
var lastLocalScanBind = binding.BindString(&lastLocalScan)
var a = app.New()
var tabs *container.AppTabs
var localNetworkPage = container.New(layout.NewVBoxLayout(), widget.NewLabel("Local Network has not yet been Scanned"))
var poisonChannels map[string](chan struct{})
var monitorChannels map[string](chan struct{})
var routers []string

//Components
var fwall Firewall
var spoofer ArpSpoofer

func main() {
	lastLocalScan = "Last Scanned: " + "Not Scanned"
	//Set Theme
	appTheme := AppTheme{}
	a.Settings().SetTheme(&appTheme)
	w := a.NewWindow("Network Discovery Tool")
	w.SetMaster()
	//Make maps
	poisonChannels = make(map[string](chan struct{}))
	monitorChannels = make(map[string](chan struct{}))
	routers = []string{}
	fwall = Firewall{}
	spoofer = ArpSpoofer{}
	//Get Local IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		fmt.Println("Fatal Error Getting IP")
	}
	localIP = conn.LocalAddr().(*net.UDPAddr).IP.String()

	//Code to build each individual page here

	//Scanner Page
	topInfo := container.New(layout.NewHBoxLayout(), widget.NewLabel("Local IP: "+localIP))
	interfaces := []string{"wlan0", "wlan1"}
	scIC := container.New(layout.NewHBoxLayout(), widget.NewLabel("Network Adapter: "), widget.NewSelect(interfaces, setInterface))
	scLN := container.New(layout.NewHBoxLayout(), widget.NewButton("Scan Local Network", scanLocalNetwork), widget.NewButton("Use Last Scan", useLastLANScan), widget.NewLabelWithData(lastLocalScanBind))
	scPage := container.New(layout.NewVBoxLayout(), topInfo, scIC, scLN)
	//Local Network Page

	//Other Networks Page

	//Final Layout Manufacturing
	tabs = container.NewAppTabs(
		container.NewTabItem("Scanner", scPage),
		container.NewTabItem("Other Networks", widget.NewLabel("Other Networks")),
	)
	tabs.SetTabLocation(container.TabLocationLeading)

	w.Resize(fyne.NewSize(700, 350))
	w.SetContent(tabs)
	w.ShowAndRun()
}

func setInterface(i string) {
	wifiInterface = i
}

//All Variables necessary to maintain page and events
var lastRun NMapRun
var selectedTargetIP string
var selectedTargetMAC string

func useLastLANScan() {
	run := readLANScan()
	lastRun = run
	buildScanPage(run)

}
func scanLocalNetwork() {
	t := time.Now()
	lastLocalScan = "Last Scanned: " + t.Format("01/02 15:04")
	//Construct Address range
	parts := strings.Split(localIP, ".")     //Separate IP by .
	ipArg := parts[0] + "." + parts[1] + "." //Use first 2
	p3, _ := strconv.Atoi(parts[2])
	if p3 > 1 {
		start := p3 - 8
		if start < 0 {
			start = 0
		}
		end := p3 + 8
		if end > 255 {
			end = 255
		}
		ipArg += strconv.Itoa(start) + "-" + strconv.Itoa(end) + "."
	} else {
		ipArg += parts[2] + "."
	}
	ipArg += "0/24" //if third > 1 make wildcard
	//Make fourth 0/24
	//--disable-arp-ping for speed on applicable networks?
	cmd := exec.Command("nmap", ipArg, "-T4", "-PS80", "-p53,80,62078,8080", "-oX", "localNetwork.xml")
	progbar := widget.NewProgressBarInfinite()
	//progbar := widget.NewProgressBar()
	progWindow := a.NewWindow("Local Network Scan")
	progWindow.SetContent(container.NewVBox(widget.NewLabel("Running Local Area Network Scan"), progbar))
	progWindow.Resize(fyne.NewSize(200, 100))
	progWindow.Show()
	_, err := cmd.Output()
	if err != nil {
		lastLocalScan = "Error: " + err.Error()
	}
	lastLocalScanBind.Reload()
	progWindow.Close()

	localNetworkPage.RemoveAll()

	run := readLANScan()
	lastRun = run
	buildScanPage(run)
}

func buildScanPage(run NMapRun) {
	hostList := widget.NewList(
		func() int {
			return len(run.HostList)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(widget.NewLabel("template"), widget.NewLabel("Unknown"), widget.NewLabel("Unknown"), widget.NewButton("Select", nil))
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			//o.(*widget.Label).SetText(run.HostList[i].Addresses[0].Addr)
			o.(*fyne.Container).Objects[0].(*widget.Label).SetText(run.HostList[i].Addresses[0].Addr)
			if len(run.HostList[i].Addresses) < 2 {
				return
			}
			o.(*fyne.Container).Objects[1].(*widget.Label).SetText(run.HostList[i].Addresses[1].Addr)

			vendor := run.HostList[i].Addresses[1].Vendor
			if vendor == "" {
				vendor = "Unkown"
			}
			o.(*fyne.Container).Objects[2].(*widget.Label).SetText(vendor)
			o.(*fyne.Container).Objects[3].(*widget.Button).OnTapped = func() {
				fmt.Printf("Selected Target: %s\n", run.HostList[i].Addresses[0].Addr)
				selectedTargetIP = (run.HostList[i].Addresses[0].Addr)
				selectedTargetMAC = run.HostList[i].Addresses[1].Addr
			}
		})

	status := widget.NewLabel("Local Network has been Scanned: " + run.Stats.Hosts.Up + " Hosts Online")
	top := container.New(layout.NewVBoxLayout(), status)
	hostListContainer := container.NewMax(hostList)
	//Bottom buttons list will be [Poison] [Monitor] [Limit] [Block] [Analyze]
	poisonBtn := widget.NewButton("Poison", poisonTarget)
	monitorBtn := widget.NewButton("Monitor", monitor)
	limitBtn := widget.NewButton("Limit", func() {})
	blockBtn := widget.NewButton("Block", blockTarget)
	analyzeBtn := widget.NewButton("Analyze", func() {})
	bottom := container.New(layout.NewHBoxLayout(), poisonBtn, monitorBtn, limitBtn, blockBtn, analyzeBtn)
	newPage := container.NewBorder(top, bottom, nil, nil, hostListContainer)
	tabs.Append(container.NewTabItem("Local Network", newPage))
}

func blockTarget() {
	go fwall.blockData(selectedTargetIP)
}
func poisonTarget() {
	go spoofer.PoisonTarget(selectedTargetIP, selectedTargetMAC)
	fwall.allowIP(selectedTargetIP)
}
func monitor() {
	fmt.Printf("monitorChannels[%s] = %v\n", getRedText(selectedTargetIP), monitorChannels[selectedTargetIP])
	go monitorTarget()

}
func monitorTarget() {
	//tshark -i Wi-Fi (for windows) -f "ip host x.x.x.x"
	//tshark -i Wi-Fi -f "eth.addr eq xx:xx:xx:xx:xx:xx"
	if monitorChannels[selectedTargetIP] != nil {
		close(monitorChannels[selectedTargetIP])
		time.Sleep(3 / 2 * time.Second)
		monitorChannels[selectedTargetIP] = nil
		return
	}
	stoppedMonitoring := make(chan struct{})
	go func(stoppedMonitoring chan struct{}) {
		filter := fmt.Sprintf("ether host %s", selectedTargetMAC)
		fName := strings.ReplaceAll(selectedTargetIP, ".", "_") + ".pcapng"
		cmd := exec.Command("tshark", "-i", "Wi-Fi", "-f", filter, "-w", fName)

		if err := cmd.Start(); err != nil {
			fmt.Printf("Error monitoring %s\n.", getRedText(selectedTargetIP))
		}
		fmt.Printf("Started monitoring %s\n", getRedText(selectedTargetIP))

		fmt.Println(getGreenText("Process Released"))
		t := time.NewTicker(1 * time.Second)
		monitorChannels[selectedTargetIP] = make(chan struct{}, 2)
		for {
			select {
			case <-monitorChannels[selectedTargetIP]:
				stoppedMonitoring <- struct{}{}
				fmt.Printf("About to send CTRL_BREAK_EVENT to Process {%s}\n", getRedText(strconv.Itoa(cmd.Process.Pid)))
				//err := cmd.Process.Signal(syscall.SIGTERM)
				err := SendInterrupt(cmd.Process.Pid)
				if err != nil {
					fmt.Printf("Error sending interrupt signal: %s\n", getRedText(err.Error()))
					return
				}
				err = cmd.Wait()
				if err != nil {
					fmt.Printf("Error waiting for process to stop: %s\n", getRedText(err.Error()))
				}
				fmt.Printf("Monitoring on %s has been stopped. Output at %s\n", getRedText(selectedTargetIP), getGreenText(fName))
				return
			default:
				<-t.C
				fmt.Printf("[Monitor] Packet Capturing on %s still active on Process %s\n", getRedText(selectedTargetIP), getRedText(strconv.Itoa(cmd.Process.Pid)))
			}
		}
	}(stoppedMonitoring)

	<-stoppedMonitoring
}

func getRedText(s string) string {
	return fmt.Sprintf("\033[1;31m%s\033[0m", s)
}
func getGreenText(s string) string {
	return fmt.Sprintf("\033[1;32m%s\033[0m", s)
}

func SendInterrupt(pid int) error {
	dll, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return fmt.Errorf("LoadDLL: %v", err)
	}
	p, err := dll.FindProc("GenerateConsoleCtrlEvent")
	if err != nil {
		return fmt.Errorf("FindProc: %v", err)
	}
	//signal.Notify()
	r, _, err := p.Call(syscall.CTRL_SHUTDOWN_EVENT, uintptr(pid))
	if r == 0 {
		return fmt.Errorf("GenerateConsoleCtrlEvent: %v", err)
	}
	return nil
}
