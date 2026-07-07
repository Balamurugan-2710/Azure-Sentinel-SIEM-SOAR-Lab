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
1. **Telemetry Generation:** Provisioned an intentionally exposed Windows Virtual Machine to the public internet to capture real-world malicious authentication traffic.
2. **Data Pipeline Pipeline:** Logged failed and successful Windows authentication attempts (Event IDs 4625 & 4624) and routed them natively via the Azure Monitor Agent to a centralized Log Analytics Workspace.
3. **SIEM Analytics:** Configured Microsoft Sentinel on top of the log data, writing custom KQL queries to establish alert thresholds for RDP brute-force velocity.
4. **Threat Intelligence Mapping:** Developed an interactive graphical workbook utilizing geographic coordinate mapping to track attacker clusters globally in real time.
5. **SOAR Containment:** Built a serverless Logic App workflow triggered dynamically upon incident creation to parse attacker IP entities, fire high-priority triage emails, and programmatically inject explicit "Deny" rules into the firewall (NSG) for automated threat mitigation.

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
