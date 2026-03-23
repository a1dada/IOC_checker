# SOC Helper

SOC Helper is a desktop application designed for information security analysts, combining tools for IOC analysis, Windows/Active Directory attribute decoding, vulnerability assessment, and technical value interpretation within a single interface.  

The application eliminates the need to use multiple fragmented services and utilities by providing a unified workspace for daily analysis, investigations, and incident handling.

<img width="1288" height="689" alt="image" src="https://github.com/user-attachments/assets/5b6b1639-8fbd-40ba-8576-d397dce35dfe" />

---

## Functionality

### IOC Analysis and Enrichment

The application provides a comprehensive set of tools for analyzing indicators of compromise:

<img width="1268" height="718" alt="image" src="https://github.com/user-attachments/assets/492b9771-9637-4b69-a4e6-0a5c623bcd50" />


- analysis of URLs, domains, and IP addresses  
- DNS information retrieval (A, MX, NS, TXT, SPF)  
- HTTP/HTTPS analysis (redirects, headers, cookies, server details)  
- TLS/SSL certificate inspection  
- WHOIS data retrieval  
- IP geolocation and provider identification  
- execution of network commands (ping, traceroute, nslookup, etc.)
  
<img width="1271" height="721" alt="image" src="https://github.com/user-attachments/assets/5ba09cb7-b7f3-43ae-9cbd-d20a5107843e" />

Integrations:

- **VirusTotal** — IOC analysis across multiple antivirus engines  
- **AbuseIPDB** — IP abuse and reputation data  
- **AlienVault OTX** — threat intelligence and pulse data  
- **URLScan** — web page analysis and behavioral inspection  

<img width="1493" height="899" alt="image" src="https://github.com/user-attachments/assets/48d15d0d-a849-4157-8851-b13e16e2843d" />

---

### Vulnerability Analysis (CVE)

A dedicated module for working with CVEs allows:

<img width="1487" height="892" alt="image" src="https://github.com/user-attachments/assets/0db5b487-374a-4826-94c2-ed7329094855" />

- retrieving vulnerability descriptions  
- quick navigation to sources (NVD, CVE.org, Vulners)  
- using CVE data as part of incident analysis  

---

### Active Directory and Windows Attribute Analysis

The application includes a set of decoders and analyzers for commonly encountered attributes and values:

<img width="1494" height="916" alt="image" src="https://github.com/user-attachments/assets/0332531a-f6b5-4228-831a-30055286bb9a" />

- **ms-Mcs-AdmPwdExpirationTime** — interpretation of LAPS expiration time  
- **msDS-SupportedEncryptionTypes** — analysis of Kerberos encryption types  
- **UserAccountControl (UAC)** — decoding account control flags  
- **Netlogon Error Codes** — interpretation of Netlogon errors  
- **SID Decoder** — SID structure analysis  
- **SDDL Decoder** — parsing of access control and security descriptors  
- **COM Objects** — information about COM objects  

<img width="1484" height="695" alt="image" src="https://github.com/user-attachments/assets/12909615-932f-4652-bb16-4855398b5b79" />


These modules enable fast interpretation of values found in logs, alerts, and system configurations.

---

### Artifact Decoding and Analysis

Built-in decoders are designed to process technical values and artifacts:

- transformation and parsing of various formats  
- analysis of values from security events  
- decoding IDS/IPS artifacts  

---

### Task Management

The application includes a lightweight built-in task manager:

- local task storage  
- note-taking functionality  
- quick access during analysis workflows  

---

### Settings

<img width="1272" height="692" alt="image" src="https://github.com/user-attachments/assets/33fefd17-323d-4241-897d-61e26d078e55" />


The application supports flexible interface and user experience customization. Several predefined color themes are available (including four base themes), allowing the interface to be adapted to user preferences or working environments. In addition to theme selection, UI elements can be customized — including button color schemes and core interface components. All settings are stored locally and automatically applied on subsequent launches, ensuring a consistent and predictable user experience.

---

## Purpose

SOC Helper is designed for:

- SOC analysts  
- Incident Response specialists  
- threat intelligence analysts  
- detection engineers / blue team  

The application simplifies routine analysis tasks and allows analysts to focus on data interpretation rather than data collection.
