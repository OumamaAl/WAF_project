
# title: "Docker-Based WAF Lab: DVWA + ModSecurity + Custom WAF"




A **hands-on web security lab** to understand how Web Application Firewalls (WAFs) work in practice. It includes:

**DVWA** (Damn Vulnerable Web App) — target application
**ModSecurity + OWASP CRS** — open-source WAF
**Custom Regex-Based WAF** — lightweight experimental WAF
**Kali Linux container** — testing & attack environment



---

#  Architecture Overview



```
Kali (attacker)
     ↓
Custom WAF 
     ↓
DVWA (target)
```



```
Kali (attacker)
     ↓
ModSecurity WAF (with OWASP CRS)
     ↓
DVWA (target)
```

---

#  Phase 0 — Setup

##  Prerequisites

* Docker and Docker Compose
* Python 3.11+

---

## Project Structure 
```
WAF-PROJECT/
│
├── attacks_FP_Tune/              # False positive testing payloads & tuning scripts
│
├── crsRules/                    # Custom OWASP CRS rules (used for ModSecurity WAF after startup)
│
├── custom_waf/                  # Custom WAF implementation
│   ├── Dockerfile.waf           # Docker build file for custom WAF
│   ├── rules.py                 # Regex-based detection rules
│   └── waf.py                   # Core WAF logic (request inspection engine)
│
├── ModSecuritycfg/              # ModSecurity configuration
│   ├── rulesCustomized/         # Custom ModSecurity rules ( only modified rule files )
│   ├── crs-setup.conf           # CRS configuration (thresholds, paranoia level )
│   └── modsecurity.conf         # Main ModSecurity engine configuration
│
├── docker-compose.yml           # Multi-container orchestration
├── dockerfile.kali              # Kali container build file
│
├── phase4.py                    # Performance & comparison testing script
│
├── requirements.txt             # Python dependencies
│
└── Readme.md                    # Project documentation
```

---


## Install dependencies

```bash
pip install -r requirements.txt
```

---

#  Running the Lab

## Step 1 — Start all services

```bash
docker-compose -f docker-compose.yml up -d
```

For starting : 

* DVWA (port 8080)
* ModSecurity WAF (port 8090)
* Custom WAF (port 8070)
* Kali container

---

#  ModSecurity WAF — Custom Rules Setup

To use **custom OWASP CRS rules without breaking startup**, follow carefully to bind the Modsecurity waf to the customized set of owasp crs rules , without breaking the waf startup :

### Step 1 — Initial run (baseline)

```bash
docker-compose -f docker-compose.yml up -d
```

### Step 2 — Enable custom rules binding

Edit `docker-compose.yml`:

=>  Uncomment this line under `waf -> volumes`:

```yaml
# - ./crsRules:/etc/modsecurity.d/owasp-crs/rules/
```

### Step 3 — Restart services

```bash
docker-compose -f docker-compose.yml up -d
```

This ensures:

* WAF starts correctly first
* Then loads  **custom CRS rules persistently**

---

#  Custom WAF

The custom WAF is built from:

```bash
./custom_waf/Dockerfile.waf
```

It:

* Uses **regex-based detection**
* Blocks on **first match**
* Logs to `/var/log/waf`

---

# Kali Container (Testing)

Access Kali shell:

```bash
docker exec -it kali /bin/bash
```

From there you can:

* Send payloads (`curl`, scripts)
* Run attack simulations
* Test WAF behavior

---

# Running Tests & Performance Comparison

To compare detection across:

* ModSecurity
* Custom WAF
* Direct DVWA

Run:

```bash
python phase4.py
```

This script:

* Sends test payloads sequentially , each path is targeted separately , the direct dvwa target , Mod Security WAF target , and the custom WAF target 
* Measures responses
* Evaluates detection behavior


#  Objectives of This Lab

* Understand **HTTP traffic inspection**
* Compare **rule-based vs behavioral vs custom detection**
* Analyze **false positives / false negatives**
* Learn **WAF tuning & rule engineering**
* Explore trade-offs between:

  * Open-source
  * Commercial-like logic
  * Custom-built systems

