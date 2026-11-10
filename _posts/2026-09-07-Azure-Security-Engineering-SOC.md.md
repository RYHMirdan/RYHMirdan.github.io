---
title: "00 — Azure Security Engineering + SOC"
date: 2026-09-07 03:30:00 -0400
categories: [SOC, Enterprise SOC Home Lab]
tags: [SOC, Blue-Team, KQL, Microsoft Sentinel, Wazuh, Azure, Active-Directory, Networking, Detection-Engineering, Atomic-Red-Team]
---

## Lab Architecture

The environment is deployed in Microsoft Azure and organized into three separate network segments within a VNet. Each subnet is reserved for a specific purpose.
The lab currently consists of three virtual machines:

- **VM-DC01 – Windows Server 2022:** Configured as the domain controller, providing Active Directory Domain Services (AD DS) and DNS for the lab environment.
- **VM-WIN11 – Windows 11 Pro:** Represents an employee workstation joined to the domain. It is used for endpoint monitoring, security testing, and simulated IT support scenarios.
- **VM-WAZUH01 – Ubuntu Server 24.04:** Hosts the Wazuh Manager, which centralizes endpoint telemetry and provides security monitoring and alerting.

The three machines are separated into Management, Workload, and Security subnets. Each subnet has an associated Network Security Group to control network traffic. This design was made with a foundation for exploring how enterprise environments separate administrative systems, user endpoints, and security infrastructure in mind.

![Azure SOC Lab Architecture](/assets/img/Azure-SOC-lab/azure-soc-architecture.png)