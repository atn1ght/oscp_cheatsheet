# RABBITMQ ENUMERATION (Port 5672)

## SERVICE OVERVIEW
```
RabbitMQ is a message broker implementing AMQP
- Default AMQP port: 5672
- Management UI: 15672 (HTTP)
- Default credentials: guest:guest (localhost only!)
- Stores messages, credentials, configuration
```

## BANNER GRABBING
```bash
nmap -sV -p5672 <IP>
nc -nv <IP> 5672
telnet <IP> 5672
```

## DEFAULT CREDENTIALS
```bash
# Default: guest:guest (only works from localhost by default!)
# Common credentials:
admin:admin
administrator:administrator
rabbitmq:rabbitmq
test:test
```

## MANAGEMENT UI (Port 15672)
```bash
# Access management interface
curl http://<IP>:15672
firefox http://<IP>:15672

# Default login: guest:guest
# API endpoints:
curl -u guest:guest http://<IP>:15672/api/overview
curl -u guest:guest http://<IP>:15672/api/users
curl -u guest:guest http://<IP>:15672/api/vhosts
curl -u guest:guest http://<IP>:15672/api/queues
```

## EXPLOITATION
```bash
# After login to management UI:
# 1. Read all messages in queues (may contain sensitive data!)
# 2. Create admin user
# 3. Reconfigure message routing
# 4. Execute commands via management plugins

# Extract messages
curl -u admin:admin http://<IP>:15672/api/queues/%2F/<queue_name>/get -d '{"count":100,"ackmode":"ack_requeue_false"}' -H "Content-Type: application/json"
```

## QUICK WIN CHECKLIST
```
☐ Check if management UI accessible (port 15672)
☐ Test default credentials (guest:guest)
☐ Brute force credentials
☐ Extract messages from queues
☐ Look for credentials in messages
☐ Check user permissions
☐ Test for CVEs (searchsploit rabbitmq)
```

## CRITICAL FINDS
```
- Messages may contain:
  * Passwords
  * API keys
  * Session tokens
  * Database queries
  * Internal communications
- Full message queue control
- Can intercept/modify application messages
```
