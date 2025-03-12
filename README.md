# SOC-Automation-Project
## Objective

This project automates SOC processes by integrating Sysmon, Wazuh, Shuffle, and TheHive. When Mimikatz is detected, the system enriches the alert, triggers automated actions, and creates a case in TheHive. SOC analysts are notified via email with a link to quarantine the infected device. This streamlines detection, response, and case management, improving overall security efficiency.

### Skills Learned

- Advanced understanding of integrating and automating security workflows using SOAR platforms.
- Proficiency in managing case creation and tracking incidents with platforms.
- Strong understanding of endpoint security through integrating EDR-like solutions for detecting advanced threats.
- Enhanced skills in configuring alerting systems and creating custom detection rules for specific threats like Mimikatz.
- Practical experience in automating incident response actions, including device quarantine and notification workflows.

### Tools Used

- Wazuh – Implemented as an SIEM and EDR solution for log ingestion, analysis, and endpoint threat detection.
- Shuffle – Configured as a Security Orchestration, Automation, and Response (SOAR) platform to automate security workflows and incident response.
- TheHive – Used for case management, incident tracking, and investigation.
- VirusTotal – Integrated for enriching security alerts with file hash analysis and threat intelligence.
- Sysmon – Implemented for advanced logging and detailed endpoint monitoring.

### Network Diagram

![image](https://github.com/user-attachments/assets/2ac59cc6-757d-4530-90d4-d436e15cebb8)

The Windows 10 client has both Sysmon and the Wazuh Agent installed. Sysmon logs are collected by Wazuh, which is hosted in the cloud. If Mimikatz is executed on the Windows client, Wazuh will detect the activity and trigger an alert. This alert is then sent to TheHive, a case management system, and an email notification is sent to the SOC analyst with all the necessary details. The analyst can quickly understand the alert and take appropriate action, such as quarantining the device if needed. This entire Security Orchestration, Automation, and Response (SOAR) process is managed using Shuffle.
