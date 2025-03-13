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
In this project, the Wazuh server is hosted on the cloud, but if you have enough resources in your system, you can also do it in a Virtual Machine.

The Ubuntu distro is used to install the Wazuh server in this case, but you can use any other distro of your choice and proceed with that installation accordingly.

```
sudo apt update && sudo apt upgrade -y
curl -s0 https://packages.wazuh.com/4.11/wazuh-install.sh && sudo b ash ./wazuh-install.sh -a
```
Take note of the credentials that show up during installation.

Now once the installation is done, you can visit the Wazuh Web interface using `https://<wazuh_IP>`. if you hosted in the cloud you can reach the Wazuh from any machine that has the internet connection and allowed by the firewall using the public ip of the machine but if you hosted in a VM then you can only visit it from the machine that are in the same network as your Wazuh Virtual Machine so keep that in mind.

![image](https://github.com/user-attachments/assets/4203b661-4e8a-4736-85c6-542bc851f7cd)

Enter the credentials that you previously noted here.

if you forgot those credentials and skipped noting that, then you can access the credentials from this file : `~/wazuh-install-files/wazuh-passwords.txt`. But at first you need to extract the `wazuh-install-files` zip file using `tar -xvf wazuh-install-files`. 


### Step 2 ~ Installing and Configuring TheHive

TheHive instance also hosted in the cloud for this project and  the availability, the same above goes for here too.

You need some prerequisite that should be installed before installing TheHive, the below is shown for the Debian Package Manager and if you wanted to use Red Hat Package Manager then you can refer the official documentation:  https://docs.strangebee.com/thehive/installation/step-by-step-installation-guide/

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
check whether it was installed properly using:
```
java -version
```
#### Installing Apache Cassandra

```
wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
```
Add the repository to your system by appending the following line to the /etc/apt/sources.list.d/cassandra.sources.list file. This file may not exist, and you may need to create it.

```
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
```

```
sudo apt update
sudo apt install cassandra
```
#### Installing Elasticsearch
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
```
Add the repository to your system by appending the following line to the /etc/apt/sources.list.d/elastic-7.x.list file. This file may not exist, and you may need to create it
```
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
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

You need to set the Listen address to your TheHive instance IP. Example: 53.43.21.2

![image](https://github.com/user-attachments/assets/d7f8924f-feaa-4240-9c35-965c854bca7e)


Set the rpc address to your TheHive instance IP addresss.

![image](https://github.com/user-attachments/assets/e4fa10b2-fac6-415f-9c71-8af96a6e6faa)

In here, change the seed IP address to yours and leave the defaul port as it is, unless you modified the default port to any other custom port.

Save and Exit.

```
sudo systemctl stop cassandra.service
sudo rm -rf /var/lib/cassandra/*
sudo systemctl start cassandra.service
sudo systemctl enable cassandra.service
```
check the status now
```
sudo systemctl status cassandra.service
```

#### Configuring Elasticsearch

```
nano /etc/elasticsearch/elasticsearch.yml
```

Change the cluster name to the same cluster name that you defined for the Cassandra.

![image](https://github.com/user-attachments/assets/65264dd2-e343-4977-86f6-a3151ced2176)

![image](https://github.com/user-attachments/assets/bbdbf8b7-bb66-441f-924e-5e098bf90d96)

The above `node.name` had been commented and you should uncomment that by removing the preceeding `#` 

![image](https://github.com/user-attachments/assets/63a346aa-f893-4bc9-aafc-3cf3df5d7b17)

The network host mentioned also had been commented, and you should uncomment that, then add TheHive instance IP address here.

![image](https://github.com/user-attachments/assets/6452fba1-a521-44d6-96f0-5f9463190e8c)

Uncomment the above.

![image](https://github.com/user-attachments/assets/0785955f-6a55-4d04-adb1-e6b2ab87c152)

Uncomment the above and remove the `node-2` as there is no need for scaling the Elasticsearch.

Save and Exit.

```
systemctl start elasticsearch
systemctl enable elasticsearch
```

#### Configuring TheHive

We need to provide the full access on `opt/thp` to TheHive

```
chown -R thehive:thehive /opt/thp
```

```
nano /etc/thehive/application.conf 
```

Now we need to make some changes on the Database and indexer.

![image](https://github.com/user-attachments/assets/b97021c0-ee9d-4d66-8e21-5653a7d149c3)

In the above change the hostname IP address to TheHive IP address and change the clustername. 

![image](https://github.com/user-attachments/assets/011a669f-d4cd-4f2f-bf1e-eb4abea4b95a)

Change the hostname IP address to TheHive IP.

![image](https://github.com/user-attachments/assets/31a482f4-e285-431a-9d7f-1f6ab1a5b8bd)

change the application.baseURL pointing to your IP.

Save and Exit.

```
sudo systemctl start thehive
sudo systemct enable thehive
```
check if it is running.
```
sudo systemctl status thehive
```

Now make sure that all the service are running so TheHive will work properly.

Access TheHive web interface using `<TheHive_IP>:9000` 

![image](https://github.com/user-attachments/assets/0d3fdde2-c96a-4142-b389-7ed1db895a68)

The above is the default credentials to login.

if it shows failed to login then make sure all the service are running  and then:

```
nano /etc/elasticsearch/jvm.options.d/jvm.options
```
Add the below content to the file:
```
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
```

This is to assign 2 GB of memory for the java, so the elasticsearch crashing won't happen again because of resource constraints.

### Step 3 ~ Installing Windows 10 Endpoint and Configuring

You can refer my previous project step for <a href="https://github.com/rohith-kumar53/Active-Directory-Home-Lab#step-1-installing-the-windows-10-virtual-machine">installing Windows 10 VM</a> and <a href="https://github.com/rohith-kumar53/Active-Directory-Home-Lab?tab=readme-ov-file#downloading-and-installing-sysmon">installing sysmon in it</a>.

#### Configuring Wazuh Agent

Login to the Wazuh Web Interface

![image](https://github.com/user-attachments/assets/b0e03b53-5914-4de7-9c29-6b6071ebba74)

![image](https://github.com/user-attachments/assets/a9ff0daf-1b3f-4d0a-b03d-f4725858971a)

Select Deploy new agent

![image](https://github.com/user-attachments/assets/b983d093-a3e3-4646-81c7-622c7fdf8881)

Select based on the Agents OS and enter the Wazuh Server IP.

![image](https://github.com/user-attachments/assets/82df5aae-4dad-4975-ab4f-2a29d5944b10)

Copy that Powershell command and paste it on the Windows Endpoint powershell and make sure that powershell run as an administrator.

![image](https://github.com/user-attachments/assets/ae8faa0c-1bd2-4bef-b308-bd4b5eff9594)

check if the wazuh service is running and change the logon as local system account so the wazuh service will have full access to do it stuffs.  

![image](https://github.com/user-attachments/assets/090f13f4-10ab-446c-b97e-faf134daa6b1)

if any changes made to the wazuh service then you must restart the wazuh service.

Now if you open the Wazuh web interface and located into agents, now you can see the Windows agent was succesfully connected to our Wazuh server.

![image](https://github.com/user-attachments/assets/92cc0de9-6a41-4d8c-82cb-49a3775e29ab)


#### Configuring Windows Telemetry

Go to : `C:\Program Files (x86)\ossec-agent` and make a backup of `ossec.conf`, like `ossec.conf.bak` So if you mess up this config file somehow then by just reverting the backup to the original file you will not break the setup.

Open notepad.exe as adminstrator and open the `C:\Program Files (x86)\ossec-agent\ossec.conf` file.

We are modifying the configuration to sent Sysmon logs by adding the below. In this case, we are only sending Sysmon events to the Wazuh server, by removing the default Security, Application and System log mentions in the config file (This is Optional).   

![image](https://github.com/user-attachments/assets/38456e15-bfdf-40e8-9fc4-ed50794aaa12)

Now restart the wazuh service.

#### Downloading Mimikatz

Add Excludion in Windows Security so we can able to download the Mimikatz from the official site.

![image](https://github.com/user-attachments/assets/2652c178-bd6b-4d9d-a16d-0010af9e233d)

![image](https://github.com/user-attachments/assets/f822b168-6ff2-4a47-b821-f6a0b93e8209)

Also disable Windows Defender Smartscreen on the browser, for Microsot Edge browser:
 
![image](https://github.com/user-attachments/assets/12bc7e63-cca3-4c89-a2c4-a6a8da939f55)

Now, We can download the mimikatz from the official github repository.

### Step 4 ~ Configuring Wazuh (Part 2)

#### Configuring Wazuh to collect all telemetry

In default wazuh doesn't log everything, we can configure to log everything so we don't miss out any events that will be important for us

Backup the ossec.conf file
```
cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf 
```

```
nano /var/ossec/etc/ossec.conf
```

![image](https://github.com/user-attachments/assets/788b1c90-5b55-43dc-bd7c-2763ba8f8f0e)

change the `logall` and `logall_json` to yes

Save and Exit.

```
systemctl restart wazuh-manager.service
```

We need to make sure all the archive logs are seding to the wazuh, so we need to modify the filebeat config.

```
sudo nano  /etc/filebeat/filebeat.yml
```

![image](https://github.com/user-attachments/assets/9900cb1f-e0e9-4a24-bd51-fa6c135040cb)

set the archives enable to true then save and exit.

```
systemctl restart filebeat
```

#### creating index in wazuh

Go to Stack Management > Index Pattern in Wazuh Web Interface.

![image](https://github.com/user-attachments/assets/2332f091-3db0-44e1-bfab-6e2e9c1c260d)

![image](https://github.com/user-attachments/assets/650d95ae-c09b-464c-b76d-ef27511a2c03)

create new index pattern by defining `wazuh-archives-**` so it will include all the pattern starts with wazuh-archives-. 

![image](https://github.com/user-attachments/assets/a374daa6-84ce-41ed-9c72-4ce8a30ff863)

select this timestamp and select create index pattern.

![image](https://github.com/user-attachments/assets/183fecdc-5859-42f5-badd-e19d48e369a2)

In the discover option, select the index which we created. 

Now we can execute the mimikatz in our windows endpoint and check in our wazuh server for the logs.

if we searched for mimikatz in the discover option with the index pattern we chosen then all the logs related to the mimikatz will be show up in our Wazuh server.

![image](https://github.com/user-attachments/assets/79cc1823-fb07-4eae-999c-bf43d760265b)

### Step 5 ~  Creating Wazuh Alerts

We can create a alert to detect mimikatz based up on the File Original Name attribute from the sysmon log. As simply changing the filename will not actually change this attribute value and comparing to other attributes this is much reliable although not foolproof since attacker can use some advanced technique to change this attribute but it is fine for now.

We will use the Graphical Interface to configure this rule and it is also done by Commandline Interface.

![image](https://github.com/user-attachments/assets/6b852822-fb6f-4463-aae6-f244af8d89b7)

Lets create a custom rule for alerts if Mimikatz was executed.

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

#### Configuring Webhook app
For the webhook app, we will only transfer the `Spotted Mimikatz Execution` alert to this webhook.

In the Wazuh server:

```
nano /var/ossec/etc/ossec.conf`
```

```
<integration>
<name>shuffle</name>
<hook_url>webhook_uri </hook_url>
<rule_id>100002</rule_id>
<alert_format>json</alert_format>
</integration>
```
Add this to the ossec.conf file and make sure that the webhook_uri is retrieved from your shuffle workflows webhook app.

```
sudo systemct restart wazuh-manager.service
```

#### Configuring HTTP app
To retrieve the api key of the wazuh server, we will use this http app.

To know your authentication credential for the wazuh:

```
cat ~/~/wazuh-install-files/wazuh-passwords.txt
```

In here, you can see the credential of your wazuh server to authentical for the Wazuh server's API.

In the http app, use curl to retrieve the api key .

```
curl -u username:password -k -X GET "https://<wazuh-IP>:55000/security/user/authenticate?raw=true"
```

#### Configuring regex

We will configure regex to only retrieve the executed mimikatz files hash without any other values to provide input for virustotal.

![image](https://github.com/user-attachments/assets/35d679b7-04ae-4bf9-8b2f-607ed276d94e)


Other regex are used to retrieve only the username and image name (This is optional)

![image](https://github.com/user-attachments/assets/9b4b019f-8230-4d3d-b278-d4165860fcbb)

![image](https://github.com/user-attachments/assets/8ae827f8-bbb0-4856-9e3b-4561159d69d4)

#### Enrichment using Virustotal
We will use Virustotal to find if it was flagged as malicious from different vendors, by using the files hash.

![image](https://github.com/user-attachments/assets/d0c250f3-6a21-4a8e-a432-9cf7fc08d707)

We can authenticate by using our Virustotal api key and we need to get the hash report which we wil use the regex value we retrieved previously as the hash value input.

#### Generating alert in TheHive
 
Login to TheHive web interface and create an Organization. For example Hello, and we will create two members one is the analyst who will investigate and other is for API purpose.

![image](https://github.com/user-attachments/assets/0bcaab13-5572-4113-8fe4-8d24db024220)

Generate the API key from the account that you want to sign it using its API key for TheHive app in the shuffle.

![image](https://github.com/user-attachments/assets/6d2d8568-d35d-47e5-a0b4-9df34c53152e)

Lets configure in the Advance > Body
Add the below data,  note i used the other regex values for username and image name, you can change that to default execution argument attributes or if you did the regex like me then you can simply leave it as it is. You can also add any more info or change the information like the way you find more interesting.

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

we will use the User Input app for this puporse and will receive the user input via the email mentioning about the threat with all the necessary IOC information. Also we will get the option to whether contaminate the device or not by using a shuffle link.

 
![image](https://github.com/user-attachments/assets/1e872daa-5bc5-48e3-b7c5-994d21c610ad)
 

#### Wazuh Active response

We will use the Wazuh active response feature to perform this automative response on the endpoint.

The reponse action in this project is to contaminate the network, so we will create a bat script that can contaminate the network. For contaminating the network, we can do it in several different ways but to be simple and effective, we will turn off the network adapter in the endpoint so it can't reach the network in any ways (As there is only one Network Interfance in the endpoint, this will be efficient).

In the endpoint agent.

```
@echo off
netsh interface set interface "Ethernet" admin=disable
```

We will add this script in `C:\Program Files (x86)\ossec-agent\active-response\bin`  naming `disable-nic` with the `.bat` extension.


In the Wazuh server:
```
nano /var/ossec/etc/ossec.conf
```

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

add this by searching for `active response` in that file and after the last default command(for better visibility) add the above command followed up by the active response tag value, which mentions the command that needs to be used for active response.

```
sudo systemctl restart wazu-manager.service
```

On the Wazuh app, you need to mention the command that needs to be executed and also the api key that you retrieved from HTTP app.

![image](https://github.com/user-attachments/assets/355a6fcf-c723-4978-bdb8-84f64652dae7)


### Step 7 ~ Automation in Action

Lets change the filename of the mimikatz to `security_app` and execute it.

![image](https://github.com/user-attachments/assets/cd214401-ce7f-4405-8ea9-3c3b486b5aad)

![image](https://github.com/user-attachments/assets/40034cf1-3c0d-4c7e-87a1-da7447bd16a7)

#### TheHive alert
if we looked at TheHive alert, we can see the Mimikatz Execution alert popped up.

![image](https://github.com/user-attachments/assets/308db667-2a88-472f-a2e8-0d08a7ce6b03)

![image](https://github.com/user-attachments/assets/de5cc6e5-a638-40e8-bef9-567a33c38aa4)

We can see, we have so much info regarding the alert including the virustotal enrichment, username, hostname, image location, etc.

#### User Input via Email

![image](https://github.com/user-attachments/assets/0dd084a2-aa64-40a2-abdf-0cc13409be5d)

We also got a userinput via email for the responsive action.

![image](https://github.com/user-attachments/assets/dc44966e-78cf-47d6-8b8f-7d185eea673f)

We have a lot of info regarding the alert and also asking us for the reponsive action whether to contaminate the device from the network or not using the provided link.

Lets use that link to give the reponse to contaminate the device from network. 



![image](https://github.com/user-attachments/assets/5207d83c-aa3e-4478-9c72-b550cc5f9cb9)

if we clicked the link, the response action will be forwarded to shuffle which will trigger the wazuh command.

#### Wazuh active response

Before providing the user input:
![image](https://github.com/user-attachments/assets/a1a02b60-26da-4bda-8264-0895ab4b5af1)

After providing the user input:

![image](https://github.com/user-attachments/assets/ee796c08-4302-469d-a432-2ba0c81bce0e)

![image](https://github.com/user-attachments/assets/a969dff2-348c-4c82-b5cc-ce9914611ee2)

The windows endpoint now succesfully contaminated from the network and we can perform further investigation without risking the attacker pivoting through the network and possibly compromising the Domain controller or what not.


