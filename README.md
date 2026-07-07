# Cloud-Native SIEM, Threat Intel, & SOAR Automation Lab

An end-to-end security engineering project demonstrating the deployment, configuration, and automation of a modern Security Operations Center (SOC) framework within Microsoft Azure. This lab features an active telemetry honeypot, live global threat visualization, custom detection engineering, and automated incident response (SOAR) containment.

---

## 🛠️ Technologies & Tools Used
* **SIEM Platform:** Microsoft Sentinel
* **Log Ingestion:** Azure Log Analytics Workspaces & Azure Monitor Agent (AMA)
* **Automation (SOAR):** Azure Logic Apps (Consumption) & Sentinel Automation Rules
* **Query Language:** Kusto Query Language (KQL)
* **Cloud Infrastructure:** Azure Virtual Machines, Network Security Groups (NSGs)
* **Threat Intelligence:** OSINT Geolocation Mapping & AbuseIPDB Data Parsing

---

## 🏗️ Architectural Overview

```mermaid
graph LR
    A[🌐 Attacker IP] -->|Brute-Force RDP| B(🖥️ Azure VM <br> vm-honeypot)
    B -->|Security Logs EventID 4625| C{📊 Log Analytics <br> Workspace}
    C -->|KQL Analytics Rule| D[🛡️ Microsoft Sentinel <br> SIEM Engine]
    D -->|Trigger Incident ID 5| E[⚡ Sentinel Automation <br> Rule]
    E -->|Run Playbook Workflow| F(⚙️ Azure Logic App <br> soar-email-alert)
    F -->|1. Email Route Notification| G[📬 SOC Analyst Inbox]
    F -->|2. Restrict Inbound Packet Flow| H[🧱 Network Security Group <br> NSG Deny Rule]
    H -.->|Drop Traffic Connection| A

    style A fill:#ffcccc,stroke:#ff3333,stroke-width:2px;
    style B fill:#ffe5cc,stroke:#ff8000,stroke-width:2px;
    style C fill:#e5ccff,stroke:#7f00ff,stroke-width:2px;
    style D fill:#cce5ff,stroke:#3333ff,stroke-width:2px;
    style F fill:#ccffcc,stroke:#33cc33,stroke-width:2px;
    style H fill:#ffcce5,stroke:#cc0066,stroke-width:2px;

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
---

## 📊 Phase 1: Threat Intelligence Visualization
The custom-designed Microsoft Sentinel Workbook maps live network brute-force attempts globally, parsing location parameters to dynamically render threat cluster densities.

![Global Threat Map](threat-map.png)

### Custom KQL Query Used for Data Extraction:
```kql
let GeoIPDB = _GetWatchlist('geoip');
SecurityEvent
| where EventID == 4625
| extend latitude = toreal(latitude), longitude = toreal(longitude)
| summarize FailedAttempts = count() by IpAddress, latitude, longitude, cityname, countryname
| where isnotempty(latitude) and isnotempty(longitude)




---

## 💡 Troubleshooting & Challenges

Building this engineering lab introduced several real-world cloud configuration challenges that required active debugging and remediation:

### 1. Microsoft Sentinel Automation Playbook Permission Error
* **Challenge:** When attempting to attach the `soar-email-alert` playbook to the scheduled analytics rule, a critical warning appeared stating: `No Microsoft Sentinel permission to run playbooks on this resource group.`
* **Resolution:** Even as a subscription owner, explicit cross-resource permissions must be assigned. Navigated to the core resource group access blade (`RG-SOC-Lab` -> Access Control IAM) and managed playbook permissions to formally grant Microsoft Sentinel authorization to execute workflows inside that target boundary container.

### 2. Single Sign-On (SSO) Authentication Pop-up Lockout
* **Challenge:** When attempting to initialize the API connection inside the Logic Apps Designer canvas card for the Microsoft Sentinel connection step, the right panel hung indefinitely on `Adding new connection...`.
* **Resolution:** Isolated the issue to the web browser's strict privacy shields blocking cross-origin identity verification pop-ups. Configured explicit URL exceptions for `portal.azure.com` within the browser address bar configuration, allowing the OAuth sign-in window to successfully render and complete the token handshake.

### 3. Logic App Token Array Misalignment ('For each' clumping)
* **Challenge:** Upon inserting the dynamic `IP Address` data token from the entity parser step into the Outlook email template body, the designer engine automatically wrapped the action inside a `For each` array block. This scrambled the plain-text body variables, clumping data tags at the header line and breaking string values.
* **Resolution:** Completely wiped the text buffer, manually re-initialized the raw structural string placeholders, and surgically re-mapped each individual system attribute (`Incident Title`, `Incident Severity`, and `IPs Address`) directly to the end of its respective clean line parameter space within the dynamic code block structure.
