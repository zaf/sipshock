### A scanner for SIP proxies vulnerable to Shellshock
---

#### Usage:
sipshock [ Flags ] [ IP Addresses ]

#### Usage flags:
- listen : Local listening address
- lport  : Local server port
- rport  : Remote port

The exec module in Kamailio, Opensips and propably every other SER fork
passes the received SIP headers as environment viarables to the invoking shell.
This makes these SIP proxies vulnerable to CVE-2014-6271 (Bash Shellshock).
If a proxy is using any of the exec funtions and has the 'setvars' parameter set to 1 (default)
then by sending SIP message containing a specially crafted header we can run arbitrary code on the
proxy machine.


This program is free software, distributed under the terms of
the GNU General Public License Version 3. See the LICENSE file
at the top of the source tree.
