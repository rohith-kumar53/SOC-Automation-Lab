# SOC-Automation-Project
## Objective

This project automates SOC processes by integrating Sysmon, Wazuh, Shuffle, and TheHive. When Mimikatz is detected, the system enriches the alert, triggers automated actions, and creates a case in TheHive. SOC analysts are notified via email with a link to quarantine the infected device. This streamlines detection, response, and case management, improving overall security efficiency.

### Skills Learned

- Advanced understanding of integrating and automating security workflows using SOAR platforms.
- Proficiency in managing case creation and tracking incidents.
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

## Steps

### Step 1 ~ Installing and Configuring Wazuh
In this project, the Wazuh server is hosted on the cloud, but you can also install it on a Virtual Machine if you have enough resources.

The Ubuntu distro is used here, but you can use any other compatible distro.

```
sudo apt update && sudo apt upgrade -y
curl -s0 https://packages.wazuh.com/4.11/wazuh-install.sh && sudo b ash ./wazuh-install.sh -a
```
Take note of the credentials that appear during installation. If you forget them, you can find them in the following file:

```
~/wazuh-install-files/wazuh-passwords.txt
```

Access the Wazuh web interface via `https://<wazuh_IP>.`

![image](https://github.com/user-attachments/assets/4203b661-4e8a-4736-85c6-542bc851f7cd)

### Step 2 ~ Installing and Configuring TheHive

You can always refer to the official documentation for more info:  https://docs.strangebee.com/thehive/installation/step-by-step-installation-guide/

#### Installing Dependencies
```
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
```
#### Installing Java Virtual Machine
```

wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

#### Installing Apache Cassandra

```
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

#### Installing Elasticsearch
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

#### Installing TheHive

```
wget -O- https://raw.githubusercontent.com/StrangeBeeCorp/Security/main/PGP%20keys/packages.key | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [arch=all signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.4 main' |sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

#### Configuring Cassandra

```
sudo nano /etc/cassandra/cassandra.yaml
```

![image](https://github.com/user-attachments/assets/38bcf425-e455-4cbc-b7c8-a484a5994130)

You can change the name of the cluster

![image](https://github.com/user-attachments/assets/9f337922-112d-42d9-92fb-5168070cb751)

- Set the listen_address and `rpc_address` to your TheHive instance IP.

- Update the `seed` IP address.

![image](https://github.com/user-attachments/assets/d7f8924f-feaa-4240-9c35-965c854bca7e)

![image](https://github.com/user-attachments/assets/e4fa10b2-fac6-415f-9c71-8af96a6e6faa)

Restart and enable Cassandra:

```
sudo systemctl stop cassandra.service
sudo rm -rf /var/lib/cassandra/*
sudo systemctl start cassandra.service
sudo systemctl enable cassandra.service
```

#### Configuring Elasticsearch

Modify the Elasticsearch configuration:

```
nano /etc/elasticsearch/elasticsearch.yml
```

- Set `cluster.name` to match Cassandra's cluster name.

- Set `network.host` to TheHive instance IP.

![image](https://github.com/user-attachments/assets/65264dd2-e343-4977-86f6-a3151ced2176)

![image](https://github.com/user-attachments/assets/bbdbf8b7-bb66-441f-924e-5e098bf90d96)

Uncomment `network.host` and Set TheHive IP Address

Remove the `#` to uncomment it:

![image](https://github.com/user-attachments/assets/63a346aa-f893-4bc9-aafc-3cf3df5d7b17)

Uncomment `http.port`

![image](https://github.com/user-attachments/assets/6452fba1-a521-44d6-96f0-5f9463190e8c)

Uncomment `cluster.initial_master_node`

![image](https://github.com/user-attachments/assets/0785955f-6a55-4d04-adb1-e6b2ab87c152)

If you find any reference to node-2, remove it. For a standalone setup, there is no need for clustering.

Run the following commands to start and enable Elasticsearch on system boot:

```
systemctl start elasticsearch
systemctl enable elasticsearch
```

#### Configuring TheHive

```
chown -R thehive:thehive /opt/thp
nano /etc/thehive/application.conf 
```

- Update database and indexer hostname and clustername.

- Set application.baseURL to TheHive IP.

![image](https://github.com/user-attachments/assets/b97021c0-ee9d-4d66-8e21-5653a7d149c3)

![image](https://github.com/user-attachments/assets/011a669f-d4cd-4f2f-bf1e-eb4abea4b95a)

![image](https://github.com/user-attachments/assets/31a482f4-e285-431a-9d7f-1f6ab1a5b8bd)

Start and enable TheHive:

```
sudo systemctl start thehive
sudo systemct enable thehive
```


Access TheHive web interface using `<TheHive_IP>:9000` 

![image](https://github.com/user-attachments/assets/0d3fdde2-c96a-4142-b389-7ed1db895a68)

The above is the default credentials to login.

If it shows failed to login, then make sure all the services are running  and then:

```
nano /etc/elasticsearch/jvm.options.d/jvm.options
```

Add the below content to the file:
```
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
```

This assigns 2 GB of memory to Java to prevent Elasticsearch from crashing due to resource constraints.

### Step 3 ~ Installing Windows 10 Endpoint and Configuring

Refer to the previous project for <a href="https://github.com/rohith-kumar53/Active-Directory-Home-Lab#step-1-installing-the-windows-10-virtual-machine">installing Windows 10 VM</a> and <a href="https://github.com/rohith-kumar53/Active-Directory-Home-Lab?tab=readme-ov-file#downloading-and-installing-sysmon">Sysmon</a>.

#### Configuring Wazuh Agent

Access the Wazuh web interface.

![image](https://github.com/user-attachments/assets/b0e03b53-5914-4de7-9c29-6b6071ebba74)

![image](https://github.com/user-attachments/assets/a9ff0daf-1b3f-4d0a-b03d-f4725858971a)

Deploy a new agent.

![image](https://github.com/user-attachments/assets/b983d093-a3e3-4646-81c7-622c7fdf8881)

Select based on the agent's OS and enter the Wazuh Server IP.

![image](https://github.com/user-attachments/assets/82df5aae-4dad-4975-ab4f-2a29d5944b10)

Copy the provided PowerShell command and execute it as an administrator on the Windows endpoint.

![image](https://github.com/user-attachments/assets/ae8faa0c-1bd2-4bef-b308-bd4b5eff9594)

Ensure the Wazuh service is running and set to log on as a local system account.

![image](https://github.com/user-attachments/assets/090f13f4-10ab-446c-b97e-faf134daa6b1)

If any changes are made to the Wazuh service, you must restart it.

Once completed, open the Wazuh web interface and navigate to the agents option. You should see the Windows agent successfully connected to the Wazuh server.

![image](https://github.com/user-attachments/assets/92cc0de9-6a41-4d8c-82cb-49a3775e29ab)


#### Configuring Windows Telemetry

Navigate to `C:\Program Files (x86)\ossec-agent` and create a backup of the ossec.conf file (e.g., ossec.conf.bak). This allows you to revert to the original configuration if needed.

Open notepad.exe as an administrator and edit the `C:\Program Files (x86)\ossec-agent\ossec.conf` file.

Modify the configuration to send Sysmon logs by adding the following lines. In this example, we are only sending Sysmon events to the Wazuh server. You may optionally remove the default Security, Application, and System log mentions from the configuration.  

![image](https://github.com/user-attachments/assets/38456e15-bfdf-40e8-9fc4-ed50794aaa12)

Restart the Wazuh service to apply the changes.

#### Downloading Mimikatz

Add an exclusion in Windows Security to allow the download of Mimikatz from the official site.

![image](https://github.com/user-attachments/assets/2652c178-bd6b-4d9d-a16d-0010af9e233d)

![image](https://github.com/user-attachments/assets/f822b168-6ff2-4a47-b821-f6a0b93e8209)

Disable Windows Defender SmartScreen on the browser. For Microsoft Edge:
 
![image](https://github.com/user-attachments/assets/12bc7e63-cca3-4c89-a2c4-a6a8da939f55)

You can now download Mimikatz from the official GitHub repository.

### Step 4 ~ Configuring Wazuh (Part 2)

#### Configuring Wazuh to Collect All Telemetry

By default, Wazuh does not log everything. We will configure it to log all events to ensure we capture any important information.

Create a backup of the ossec.conf file:
```
cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf 
```

Edit the ossec.conf file:
```
nano /var/ossec/etc/ossec.conf
```

![image](https://github.com/user-attachments/assets/788b1c90-5b55-43dc-bd7c-2763ba8f8f0e)

Change the `logall` and `logall_json` values to yes.

Save and exit the editor, then restart the Wazuh manager service:

```
systemctl restart wazuh-manager.service
```

Next, modify the Filebeat configuration to ensure all archive logs are sent to Wazuh.

```
sudo nano  /etc/filebeat/filebeat.yml
```

![image](https://github.com/user-attachments/assets/9900cb1f-e0e9-4a24-bd51-fa6c135040cb)

Set `archives.enable` to `true`, then save and exit.

Restart the Filebeat service:

```
systemctl restart filebeat
```

#### Creating an Index in Wazuh

Open the Wazuh web interface and navigate to Stack Management > Index Patterns.

![image](https://github.com/user-attachments/assets/2332f091-3db0-44e1-bfab-6e2e9c1c260d)

![image](https://github.com/user-attachments/assets/650d95ae-c09b-464c-b76d-ef27511a2c03)

Create a new index pattern using `wazuh-archives-**`. This will match all patterns beginning with `wazuh-archives-`.

![image](https://github.com/user-attachments/assets/a374daa6-84ce-41ed-9c72-4ce8a30ff863)

Select the appropriate `timestamp` and create the index pattern

![image](https://github.com/user-attachments/assets/183fecdc-5859-42f5-badd-e19d48e369a2)

In the Discover section, select the new index pattern. You should now see all logs, including those related to Mimikatz, when executed on a Windows endpoint.

If you search for "mimikatz" under the new index pattern, all logs related to Mimikatz execution will be displayed on the Wazuh server.

![image](https://github.com/user-attachments/assets/79cc1823-fb07-4eae-999c-bf43d760265b)

### Step 5 ~  Creating Wazuh Alerts

We can create an alert to detect Mimikatz based on the File Original Name attribute from the Sysmon log. Simply changing the filename will not alter this attribute value, making it a more reliable detection method. Although an attacker could potentially use advanced techniques to modify this attribute, it is sufficient for our current needs.

We will use the graphical interface to configure this rule, although it can also be done via the command-line interface.

![image](https://github.com/user-attachments/assets/6b852822-fb6f-4463-aae6-f244af8d89b7)

Let's create a custom rule to generate alerts when Mimikatz is executed.

```
  <rule id="100002" level="13">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Spotted Mimikatz Execution</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
```

### Step 6 ~ SOAR Implementation using Shuffle

![image](https://github.com/user-attachments/assets/edf0b118-5a63-45ef-88d8-3c32ca987eb2)

#### Configuring the Webhook App
For the webhook app, we will only forward the "Spotted Mimikatz Execution" alert.

On the Wazuh server, edit the configuration file:

```
nano /var/ossec/etc/ossec.conf`
```

Add the following integration block:

```
<integration>
<name>shuffle</name>
<hook_url>webhook_uri </hook_url>
<rule_id>100002</rule_id>
<alert_format>json</alert_format>
</integration>
```
Ensure that webhook_uri is the URL retrieved from your Shuffle workflow's webhook app.

Restart the Wazuh manager service to apply the changes:

```
sudo systemct restart wazuh-manager.service
```

#### Configuring HTTP app
To retrieve the Wazuh server's API key, we will use the HTTP app.

Find your Wazuh server credentials:

```
cat ~/~/wazuh-install-files/wazuh-passwords.txt
```

In here, you can see the credential of your wazuh server to authentical for the Wazuh server's API.

Use curl to authenticate and retrieve the API key:
```
curl -u username:password -k -X GET "https://<wazuh-IP>:55000/security/user/authenticate?raw=true"
```

#### Configuring regex

We will configure regex to extract the hash of the executed Mimikatz file for input into VirusTotal.

![image](https://github.com/user-attachments/assets/35d679b7-04ae-4bf9-8b2f-607ed276d94e)

Other regex patterns can be used to extract the username and image name.

![image](https://github.com/user-attachments/assets/9b4b019f-8230-4d3d-b278-d4165860fcbb)

![image](https://github.com/user-attachments/assets/8ae827f8-bbb0-4856-9e3b-4561159d69d4)

#### Enrichment using VirusTotal
We will use VirusTotal to determine if the hash is flagged as malicious by various vendors.

![image](https://github.com/user-attachments/assets/d0c250f3-6a21-4a8e-a432-9cf7fc08d707)

Authenticate with your VirusTotal API key and submit the hash obtained via regex for analysis.

#### Generating Alerts in TheHive
 
Log in to TheHive web interface and create an organization (e.g., "Hello"). Add two members: one for the analyst and another for API access.

![image](https://github.com/user-attachments/assets/0bcaab13-5572-4113-8fe4-8d24db024220)

Generate an API key from the API user's account for integration with Shuffle.

![image](https://github.com/user-attachments/assets/6d2d8568-d35d-47e5-a0b4-9df34c53152e)

In the Shuffle advanced settings, add the following payload in the "Body" section

```
{
  "description": " $exec.title on Computer: $exec.text.win.system.computer by the User: $username_regex.group_0.# ",
  "externallink": "",
  "flag": false,
  "pap": 2,
  "severity": 2,
  "source": "Wazuh",
  "sourceRef": "Rule: 100002",
  "status": "New",
  "summary": " $exec.title on Host: $exec.text.win.system.computer, executed by User: $username_regex.group_0.# with the process name: $image_name_regex.group_0.# ( PID: $exec.text.win.eventdata.processId ). It was detected as malicious by VirusTotal, with
$virustotal_v3_1.#.body.data.attributes.last_analysis_stats.malicious vendors flagging it. It was executed from   $exec.text.win.eventdata.image, indicating a potential credential dumping attempt.",
  "tags": ["T1003"],
  "title": " $exec.title ",
  "tlp": 2,
  "type": "Internal",
  "date": "$exec.all_fields.full_log.win.eventdata.utcTime"
}
```

Save the workflow.

#### User input

We will use the User Input app to receive user confirmation via email regarding the threat. The email will contain relevant Indicators of Compromise (IoCs) and a link to initiate a response action.
 
![image](https://github.com/user-attachments/assets/1e872daa-5bc5-48e3-b7c5-994d21c610ad)
 

#### Wazuh Active response

We will use Wazuh's active response feature to automatically isolate the compromised endpoint.

On the endpoint agent, create a script to disable the network adapter:

```
@echo off
netsh interface set interface "Ethernet" admin=disable
```

Save the script in the following location with the name `disable-nic.bat`:

```
C:\Program Files (x86)\ossec-agent\active-response\bin
```

On the Wazuh server, update the configuration:

```
nano /var/ossec/etc/ossec.conf
```
Add the following command and active response:

```
  <command>
    <name>disable-nic</name>
    <executable>disable-nic.bat</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>disable-nic</command>
    <location>local</location>
    <level>15</level>
    <timeout>no</timeout>
  </active-response>
```

Restart the Wazuh manager service:

```
sudo systemctl restart wazu-manager.service
```

On the Wazuh App in Shuffle, you need to mention the command that needs to be executed and also the api key that you retrieved from the HTTP app.

![Screenshot 2025-03-13 181939](https://github.com/user-attachments/assets/e4279b0a-9726-4569-9ed3-74cbcc118654)



### Step 7 ~ Automation in Action

To test the system, rename Mimikatz to `security_app` and execute it.

![image](https://github.com/user-attachments/assets/cd214401-ce7f-4405-8ea9-3c3b486b5aad)

![image](https://github.com/user-attachments/assets/40034cf1-3c0d-4c7e-87a1-da7447bd16a7)

#### TheHive alert
Check TheHive interface to confirm the alert is generated with enriched information from VirusTotal and Wazuh

![image](https://github.com/user-attachments/assets/308db667-2a88-472f-a2e8-0d08a7ce6b03)

![image](https://github.com/user-attachments/assets/de5cc6e5-a638-40e8-bef9-567a33c38aa4)


#### User Input via Email
An email alert is sent requesting user action to isolate the endpoint. Clicking the provided link triggers the Wazuh active response command via Shuffle.

![image](https://github.com/user-attachments/assets/0dd084a2-aa64-40a2-abdf-0cc13409be5d)

![image](https://github.com/user-attachments/assets/dc44966e-78cf-47d6-8b8f-7d185eea673f)

![image](https://github.com/user-attachments/assets/5207d83c-aa3e-4478-9c72-b550cc5f9cb9)


#### Wazuh active response

Before providing the user input:
![image](https://github.com/user-attachments/assets/a1a02b60-26da-4bda-8264-0895ab4b5af1)

After providing the user input:

![image](https://github.com/user-attachments/assets/ee796c08-4302-469d-a432-2ba0c81bce0e)

![image](https://github.com/user-attachments/assets/a969dff2-348c-4c82-b5cc-ce9914611ee2)

Before user confirmation, the network interface is active. After user confirmation, the network interface is successfully disabled, isolating the endpoint and preventing further network communication.

This automation allows for rapid containment of potential threats, mitigating risks like lateral movement and domain controller compromise.


