# Oxcart-Cybersecurity-Lab
A cloud-based cybersecurity lab built on AWS for security monitoring, detection engineering, incident response, and controlled attack simulation using Wazuh, network segmentation, and a hardened web application.



## Project Objectives

The main objectives of OxCart are to:

- Build and secure a realistic AWS network environment
- Apply network segmentation and least-privilege access controls
- Deploy and harden a web application
- Centralize application, web server, and host security logs
- Implement SIEM monitoring with Wazuh
- Generate and investigate controlled security events
- Develop custom detection rules and alerts
- Perform controlled attack simulations against the environment
- Investigate security incidents using collected telemetry
- Eventually experiment with network intrusion detection and anomaly detection

---

## Architecture

```text
                         Internet
                            |
                            v
                 +---------------------+
                 |      Bastion        |
                 |  Public Subnet      |
                 |                     |
                 |  Reverse Proxy      |
                 |  NAT Gateway Role   |
                 +----------+----------+
                            |
              +-------------+-------------+
              |                           |
              v                           v
     +------------------+       +------------------+
     |   App Server     |       |  Wazuh Server   |
     |  Private Subnet  |       |  Private Subnet  |
     |                  |       |                  |
     | Nginx            |       | Wazuh Manager    |
     | Flask            |       | Wazuh Indexer    |
     | SQLite           |       | Wazuh Dashboard  |
     | Wazuh Agent      |       |                  |
     +------------------+       +------------------+
              |
              |
              v
        Application Logs
        Nginx Logs
        Auth Logs
        Host Telemetry
              |
              +-----------------------> Wazuh
