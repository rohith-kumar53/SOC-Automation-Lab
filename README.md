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
systemctl restar wazuh-manager.service
```

We need to make sure all the archive logs are seding to the wazuh, so we need to modify the filebeat config.

```
sudo nano  /etc/filebeat/filebeat.yml
```

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

####
