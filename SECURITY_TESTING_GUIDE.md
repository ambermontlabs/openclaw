# OpenCLAW Security Testing Guide

**Date**: 2024  
**Version**: 1.0  
**Target Audience**: Security Engineers, Developers

---

## Quick Start: Test OpenCLAW with Kali Linux Tools

### Prerequisites
```bash
# Install Kali Linux tools (or use Docker)
docker run -it kalilinux/kali-rolling bash

# Inside container
apt update && apt install -y \
  burpsuite \
  owasp-zap \
  sqlmap \
  nuclei \
  ffuf \
  nmap
```

---

## 🚀 5-Minute Security Test

### Step 1: Start OpenCLAW
```bash
cd /workspace/project/openclaw
npm run dev
```

### Step 2: Run Automated Scan (5 minutes)
```bash
# Using OWASP ZAP
zap-baseline.py \
  -t http://localhost:3000/api/ \
  -r zap-report.html

# Using Nuclei
nuclei -u http://localhost:3000 \
  -t templates/openclaw-injection.yaml
```

### Step 3: Manual Testing with Burp Suite (15 minutes)
1. Start Burp Suite
2. Configure proxy to intercept requests
3. Test `/api/system/run` endpoint with:
   - `ls; cat /etc/passwd`
   - `<script>alert(1)</script>`
4. Test `/api/files` endpoint with:
   - `../../../etc/passwd`
5. Check response for injection success

### Step 4: Generate Report
```bash
# Create security report
cat > security-report.md << 'EOF'
# OpenCLAW Security Test Report

## Date: $(date)
## Tester: Automated + Manual

### Findings:
- [ ] Command Injection
- [ ] XSS
- [ ] Path Traversal
- [ ] SSRF

### Recommendations:
1. Implement input validation
2. Add WAF rules
3. Enable security headers

### Tools Used:
- OWASP ZAP
- Burp Suite
- Nuclei
EOF

cat security-report.md
```

---

## 🔍 Detailed Security Tests

### Test 1: Command Injection

#### Automated (Nuclei)
```bash
# Create template
cat > templates/openclaw-command-injection.yaml << 'EOF'
id: openclaw-command-injection

info:
  name: OpenCLAW Command Injection
  author: security-team
  severity: critical

requests:
  - method: POST
    path:
      - "{{BaseURL}}/api/system/run"
    headers:
      Content-Type: application/json
    body: |
      {"command":"ls","args":["-l; cat /etc/passwd"]}
    matchers:
      - type: word
        words:
          - "root:"
EOF

# Run test
nuclei -u http://localhost:3000 \
  -t templates/openclaw-command-injection.yaml
```

#### Manual (Burp Suite)
1. Intercept `/api/system/run` request
2. Send to Repeater
3. Try payloads:
   ```
   {"command":"ls","args":["-l; whoami"]}
   {"command":"cat","args":["/etc/passwd; ls"]}
   ```

#### Automated (sqlmap)
```bash
# Test command injection
sqlmap -u "http://localhost:3000/api/system/run" \
  --data='{"command":"ls","args":["-l"]}' \
  --level=5 --risk=3
```

---

### Test 2: XSS (Cross-Site Scripting)

#### Automated (ZAP)
```bash
zap-baseline.py \
  -t http://localhost:3000/api/agent/message \
  -r xss-report.html
```

#### Manual (Burp Suite)
1. Intercept `/api/agent/message` request
2. Send to Intruder
3. Use XSS payloads:
   ```
   <script>alert(1)</script>
   "><img src=x onerror=alert(1)>
   javascript:alert(1)
   <svg onload=alert(1)>
   ```

#### Automated (Nuclei)
```yaml
# templates/openclaw-xss.yaml
id: openclaw-xss

requests:
  - method: POST
    path:
      - "{{BaseURL}}/api/agent/message"
    headers:
      Content-Type: application/json
    body: |
      {"message":"<script>alert(1)</script>"}
    matchers:
      - type: word
        words:
          - "<script>"
```

---

### Test 3: Path Traversal

#### Automated (ffuf)
```bash
# Fuzz file paths
ffuf -u "http://localhost:3000/api/files/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -e .txt,.json,.md

# Test traversal
ffuf -u "http://localhost:3000/api/files/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -e /etc/passwd
```

#### Manual (Burp Suite)
1. Intercept `/api/files` request
2. Try payloads:
   ```
   /etc/passwd
   ../../etc/passwd
   ../../../etc/shadow
   ```

#### Automated (Nuclei)
```yaml
# templates/openclaw-path-traversal.yaml
id: openclaw-path-traversal

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/files/../../../etc/passwd"
```

---

### Test 4: SSRF (Server-Side Request Forgery)

#### Automated (ZAP)
```bash
zap-baseline.py \
  -t http://localhost:3000/api/web/fetch \
  -r ssrf-report.html
```

#### Manual (Burp Suite)
1. Intercept `/api/web/fetch` request
2. Try payloads:
   ```
   http://127.0.0.1:8080/admin
   http://169.254.169.254/latest/meta-data/
   file:///etc/passwd
   ```

#### Automated (Nuclei)
```yaml
# templates/openclaw-ssrf.yaml
id: openclaw-ssrf

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/web/fetch?url=http://127.0.0.1:8080/admin"
```

---

### Test 5: SQL Injection

#### Automated (sqlmap)
```bash
# Test database queries
sqlmap -u "http://localhost:3000/api/query" \
  --data="query=SELECT * FROM users WHERE id=1" \
  --level=5 --risk=3

# Test memory storage
sqlmap -u "http://localhost:3000/api/memory" \
  --dbms=sqlite
```

#### Manual (Burp Suite)
1. Intercept `/api/query` request
2. Try payloads:
   ```
   SELECT * FROM users WHERE id=1 OR 1=1
   SELECT * FROM users WHERE id=1 UNION SELECT * FROM passwords
   ```

---

## 📊 Security Testing Checklist

### Automated Tests
- [ ] Run OWASP ZAP baseline scan
- [ ] Run Nuclei vulnerability scanner
- [ ] Test with sqlmap for SQL injection
- [ ] Run ffuf fuzzer on endpoints
- [ ] Check dependencies with Snyk

### Manual Tests
- [ ] Test command injection with Burp Repeater
- [ ] Test XSS with Burp Intruder
- [ ] Test path traversal with ffuf
- [ ] Test SSRF with manual payloads
- [ ] Test API authentication bypass

### AI-Specific Tests
- [ ] Test prompt injection
- [ ] Test jailbreak attempts
- [ ] Test model poisoning

---

## 🛠️ Security Testing Scripts

### Quick Scan Script
```bash
#!/bin/bash
# security-scan.sh

echo "=== OpenCLAW Security Scan ==="
echo "Starting at $(date)"

# Start OpenCLAW
echo "[*] Starting OpenCLAW..."
npm run dev &

# Wait for server to start
sleep 5

# Run automated scans
echo "[*] Running OWASP ZAP scan..."
zap-baseline.py -t http://localhost:3000/api/ -r zap-report.html

echo "[*] Running Nuclei scan..."
nuclei -u http://localhost:3000

# Generate report
echo "[*] Generating security report..."
cat > security-report.md << EOF
# OpenCLAW Security Test Report

## Date: $(date)
## Scanner: OWASP ZAP + Nuclei

### Automated Scan Results:
- Check zap-report.html for detailed results
- Check nuclei output for vulnerabilities

### Manual Testing Required:
1. Burp Suite testing
2. API endpoint testing
3. AI-specific tests

### Recommendations:
1. Implement input validation
2. Add WAF rules
3. Enable security headers

## Tools Used:
- OWASP ZAP
- Nuclei
- Burp Suite (manual)
EOF

echo "[*] Security scan complete!"
echo "[*] Report: security-report.md"
```

### CI/CD Integration
```yaml
# .github/workflows/security-test.yml
name: Security Testing

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # Install dependencies
      - name: Install Dependencies
        run: npm install
      
      # Run security tests
      - name: Run OWASP ZAP
        uses: zaproxy/zap-baseline-action@v1.0.0
        with:
          target: http://localhost:3000/api/
      
      - name: Run Nuclei
        uses: projectdiscovery/nuclei-action@v1
      
      # Upload results
      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: |
            zap-report.html
            nuclei-report.json
```

---

## 📈 Security Metrics

### Track These Metrics
- Number of injection attempts blocked
- False positive rate
- Time to detect vulnerabilities
- Coverage percentage

### Example Dashboard
```yaml
# security-dashboard.yml
metrics:
  - name: injection_attempts_blocked
    type: counter
    description: Total number of injection attempts blocked
    
  - name: false_positives
    type: counter
    description: Number of false positive detections
    
  - name: vulnerabilities_found
    type: counter
    description: Number of vulnerabilities found
    
  - name: scan_coverage
    type: gauge
    description: Percentage of endpoints scanned
```

---

## 🆘 Emergency Response

### If Vulnerability Found:
1. **Isolate** affected systems
2. **Block** malicious IPs
3. **Revoke** compromised credentials
4. **Patch** vulnerability
5. **Monitor** for re-infection

### Contact Information
- Security Team: security@openclaw.example.com
- Emergency: +1-555-SECURITY

---

## 📚 Additional Resources

### Documentation
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Burp Suite Docs: https://portswigger.net/burp/documentation
- Nuclei Docs: https://docs.nuclei.sh/

### Training
- PortSwigger Academy: https://portswigger.net/web-security
- Hack The Box: https://www.hackthebox.com/

### Tools
- Kali Linux: https://www.kali.org/
- OWASP ZAP: https://www.zaproxy.org/
- Burp Suite: https://portswigger.net/burp

---

*This guide provides practical steps for testing OpenCLAW security using industry-standard tools. Regular testing is recommended to maintain strong security posture.*
