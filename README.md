
![Logo](https://images.credly.com/images/ee741c0c-3d57-48e0-82e0-699a2170aa50/AWS-Security-Specialty-2020.png)


# AWS Security

This course demonstrates how to efficiently use AWS security services to stay secure in the AWS Cloud. The course focuses on the security practices that AWS recommends for enhancing the security of your data and systems in the cloud. The course highlights the security features of AWS key services including compute, storage, networking, and database services. You will also learn how to leverage AWS services and tools for automation, continuous monitoring and logging, and responding to security incidents.

Jun 23, 2021

---

# Table of Contents

- [Day 1](#Day1)

    * [Module 1: Security on AWS](#SecurityOnAWS)


    * [Module 2: Identifying Entry Points on AWS](#IdEntryPts)


    * [Module 3: Security Considerations for Web Applications](#SecforWebApp)


    * [Module 4: Application Security](#AppSec)


    * [Module 5: Data Security](#DataSec)

- [Day 2](#Day2)

    * [Module 6: Securing Network Communications](#securenetwork)


    * [Module 7: Monitoring and Collecting Logs on AWS](#collectLogs)


    * [Module 8: Processing Logs on AWS](#processLog)


    * [Module 9: Security Considerations: Hybrid Environments](#hybridEnv)


    * [Module 10: Out-Of-Region Protection](#oorPro)

- [Day 3](#Day3)

    * [Module 11: Security Considerations for Serverless Environements](#severless)


    * [Module 12: Threat Detection and Investigation](#threatdetect)


    * [Module 13: Secrets Management on AWS](#secret)


    * [Module 14: Automation and Security by Design](#autosec)


    * [Module 15: Account Management and Provisioning on AWS](#acctnmngt)

---

## Day1 <a name="Day1"></a>

* Security on AWS<a name="SecurityOnAWS"></a>
    * Security In the AWS Cloud

        * Confidentiality, Integrity, Availability
        * Visibility, Auditibility, Controllability, Agility, Automation
            * Visibility: Use AWS Config
            * Auditabilit: Use AWS CloudTrail
            * Controllability: Use AWS IAM
            * Agility & Automation: Use AWS CloudFormation
        * AWS Resources
            * [AWS Config](https://aws.amazon.com/config/)
            * [AWS CloudTrail](https://aws.amazon.com/cloudtrail/)
            * [AWS IAM](https://aws.amazon.com/iam/)
            * [AWS CloudFormation](https://aws.amazon.com/cloudformation/)

    * AWS Shared Responsibility Model

        ![Model](https://www.hackerone.com/sites/default/files/inline-images/image3_14.png)
        ![Model](https://www.topdownsystems.com/hubfs/AWS-shared-security-model-container-services.jpg)
        ![Model](https://files.speakerdeck.com/presentations/c4ef539298a44d038815d7c60d231bdc/slide_5.jpg)
        ![Model](https://image.slidesharecdn.com/ism206-151009004018-lva1-app6892/95/ism206-modern-it-governance-through-transparency-and-automation-15-638.jpg?cb=1444784994)

    * Incident Response Overview

        * AWS Cloud Adoption Framework Security Perspective
            * Directive. What are your security requirements?
            * Detective. Look for bad things
            * Preventive. Stop bad things from happening
            * Responsive _ Fix or alert bad things detected
        * Common Incidents
            * Compromsied User Credentials
            * Insufficient Data Integrity
            * Overly Permissive Access
        * Incident Indications
            * Logs and Monitors, Billing Activity, Threat Intel, AWS Support, Ad hoc contact

    * DevOps with Security Engineering
        * CICD
        * STRIDE
            * Spoofing - Authentication
            * Tampering - Integrity
            * Repudiation - Confirmation
            * Information Disclosure - Confidentiality
            * Denial of Service - Availability
            * Elevation of privilege - Authorization
            * [CMI References](https://insights.sei.cmu.edu/blog/threat-modeling-12-available-methods/)
        * AWS Services DO NOT require penetration testing permissions
            * EC2, NAT, ELB, RDS, CloudFront, Aurora, API Gateway, Lambda, Lambda Edge, Lightsail, Elastic Beanstalk
            * NOT ALLOW: DNS Zone Walking, DoS/DDoS, Port/Protocol/Request Flooding

* Module 2: Identifying Entry Points on AWS<a name="IdEntryPts"></a>

    * Entry Points: Console, SDk, AWS CLI, API
        * Programmatic Access: SDK, AWS CLI, API
    * CloudTrail enables to capture API Calls
    * Some AWS Services do not support region. For example, CloudFront, IAM, WAF
    * Secure API vai sigining
    * IAM
        * Users, Groups, Policy
        * Policies
            * Identity-Based Policy
                * Grant permission to certain tasks
                * Specify User, Group, Role
            * Resource-Based Policy
                * Grant permission to the principle. Principle is an AWS account, user, role, or federated user
            * Inline Policy
                * Embed in a principal entity
                * Strict to one-to-one relationship between policy and entity
            * Add conditions like time, MFA, sourceIP ...etc
        * Credentials
            * Long Term Credentials
                * Username / Password / API Access Key
        * Roles
            * Collection of permissions
            * Roles are temporary credential to access resources or use API
            * Control least privilege access
            * Attach Policy under the role and in the JSON file to define the scope.
            * Set Permission Boundary to the role
            * Common Use
                * Cross-Account Access
            * Session Policies
                * Resulting permissions are the intersection of Identity-Based and Session Policy
        * Root Account:
            * Do not use root account on daily basis
            * Create IAM Users
            * Create Strong Password
            * Enable MFA
        * IAM User
            * User can have 2 access keys.
            * Trust Policy: Who is allowed to assume the role
            * Permission Policy: Which action and resources the one assuming the role is allowed to do
    * IAM Policy
    ![Model](https://docs.aws.amazon.com/IAM/latest/UserGuide/images/PolicyEvaluationHorizontal.png)
        * Types: AWS-Managed, Customer-Managed, Inline
        * Granting Access
            * User Authentication
            * User Authorization: Identity-Based Policy, Resource-Based Policy
            * Actions allowed: console, CLI, API
            * Resources: Instance, Role, S3 Bucket
            * Effect: Allow, Deny
        * IAM Requirements:
            * Must Have: Effect, Action, Resources
            * Optional: Condition, Principal
        * [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
            * NotAction is not Deny. Excluding something from the list.
        * Use Roles and Federation instead of creating IAM User
        * Use Customer-Managed Policies instead of inline policies
        * Permission Boundary
            * Restrict the permissions of the users and roles.
    * API Logging with CloudTrail
        * [CloudTrail](https://aws.amazon.com/cloudtrail/)  is a web service that records API calls made on your account
        * Log Consolidation
            * All region logs to one region
            * All account logs to one account
        * Best Practices
            * Send log to Amazon S3 for storage and log retention
            * Centralized collecting of logs to a dedicated account
            * Enforce least privilege principle
            * Enfore MFA delete on the log S3 bucket
            * Enforce Amazon S3 versioning
        * Log File Integrity by hashing the log files
        * IAM user attempt will be recorded by CT. Fail attempt to log into Root Account is not capture. Successful Root account authentication will be recorded. If MFA is enable on root account, CloudTrail will be able to record the fail attempt.

* Module 3: Security Considerations for Web Applications<a name="SecforWebApp"></a>
    * ELB Types: ALB, NLB, CLB
    * Risk Assessment
        * Identify Assets, Identify Vulnerability, and Identify Threat
    * Theat Modeling Process
        * Assign a Security POC > Fill out data flow table > Perform a threat modeling > Document Vulnerabilities
        ![Threat Model](https://michenriksen.com/assets/images/drawio/dfd.png)
        * Securing the VPC
            * NACL, Private/Public Subnets, ELB
        * Secure the Instance
            * Patches, Update, Services, Protocols, Accounts, Monitoring, Logging, Ports, Security Group
        * Secure Application
            * Authentication, Authorization, Sensitive Data, Cryptography, Session Management, Monitoring, Logging, Configuration
        * Secure Database
            * Authenticaton, Configuration, Sensitive Data
        * AWS Resources
            * [AWS Trusted Advisor](https://docs.aws.amazon.com/awssupport/latest/user/get-started-with-aws-trusted-advisor.html)
                * Service Limits
                * Fault Tolerance
                * Security
                * Performance
                * Cost Optimization
            * [AWS IQ](https://iq.aws.amazon.com/)

* Module 4: Application Security<a name="AppSec"></a>
    * Secure EC2 and application
        * Key Pair
        * SSO
        * Instance Metadata Service (IMDS) v2 protect against
            * Open Website Application Firewalls
            * Open Reverse Proxies
            * SSRF Vulnerabilites
            * Open Layer 3 FW and NATs
        * Amazon Machine Images
            * Amazon Linux AMI > Launch EC2 > Security Config + Patches > Hardened EC2 > Custom AMI / Golden Copy
            * Software Packages and Updates
            * Password Policies
            * SSH Keys
            * File System Permission / Ownership
            * User / Group Configuration
            * Access Control Settings
            * Continuous Monitoring Tools
            * Firewall Rules
            * Running Services
            * [AWS OpsWork](https://docs.aws.amazon.com/opsworks/)
            * [AWS Marketplace](https://aws.amazon.com/marketplace)
            * Community AMIs
        * Hide instance under ELB
    * Assess Vulnerabilities
        * AWS Inspector
            * Getting Started
                * Install agent on all EC2 instances > Role is used by Inspector > Tag all EC2 for scan > Define schedule assessment
            * [AWS Inspector](https://docs.aws.amazon.com/inspector/index.html) automated assessment to improve security and compliance of applications
        * AWS System Manager
            * Functions
                * System inventory
                * OS patch updates
                * Automtaed AMI creastion
                * OS and application configuration
                * Session Manager
            * Getting Started
                * Create instance profile with IAM role
                * Attach EC2 profile to instnace
                * Install SSM Agent
    * Apply instance security check via AWS Systems Manager

* Module 5: Data Security<a name="DataSec"></a>

    * Protect data at rest via encryption and access control
        * S3
            * Threat: Information Disclosure
                * Mitigation: IAM/Resource-based policies, Encryption
            * Threat Data Integrity Compromise
                * Mitigation: IAM/Resource-based policies, Encryption/Replication, Versioning (S3)
            * Threat: Accidental Deletion
                * Mitigation: IAM/Resource-based policies, Versioning (S3)
            * Threat: System/HW/SW Availability
                * Mitigation: Replication, Snapshots/Backups
            * Client Side Encryption
                * Client encrypts the data and store in the S3
            * Server Side Encryption
                * AWS encrypts the object data. Metadata is not encrypted.
                * Server Side Encryption S3. S3 create, manages, and uses (Master Key) for you. Symmetric key is used. AWS KMS generates Data Key and S3 Default Master Key. Data is brought from customer via HTTPS. S3 uses Data key from KMS with AES256 to encrypt the S3 data.
                ![](https://www.oreilly.com/library/view/aws-certified-solutions/9781789130669/assets/a41736c9-c0c6-4ad2-aec8-c31aad410c44.png)
                * Server Side Encryption KMS (AWS Managed CMK). Customer can requests the master key. AWS KMS generates Data Key, CMK, and Key Usage Policy. Data is brought from customer via HTTPS. S3 uses Data key from KMS with AES256 to encrypt the S3 data.
                ![](https://www.oreilly.com/library/view/aws-certified-solutions/9781789130669/assets/0faf29ee-4a0b-4a29-99f5-c4e1ec042047.png)
                * Server Side Encryption C (Customer Controlled Master Key). Customer creates the data key. S3 uses customer data key to encrypt the S3 data.
                ![](https://media.amazonwebservices.com/blog/2014/s3_sse_customer_key_2.png)
                * Convenience: SSE-S3 has max convenient. SSE-C has maximum control.
            * S3 Resource Protection
                * Object ACLs. If object is not own by the bucket owner
                * Bucket ACLs. Grant log delivery group write permissions to bucket
                * Bucket Policies. Cross Account access to bucket
                * IAM Policies
            * S3 Versioning
                * New version with every upload
                * Protect from uninteded user deletes
                * Easy retrieval of deleted objects
                * May use lifecycle policies for cost saving
            * S3 Object Lock
                * Store object using WORM model. (Write once read many)
                * Works only in versioned buckets
                * Ability to manage object retention
                * Two retention modes
                    * Governance: specific IAM permissions can remove object locks
                    * Compliance: protection cannot be removed by any user, including the root account
            * AWS KMS
                * AWS-Owned
                * AWS-Managed CMK
                * Customer-Managed CMK
            * Cross-Region Replication protect against
                * Compliance Requirements
                * Disaster Recovery
                * Unintentional or malicious data deletion
            * AWS S3 Access Analyzer
                * Monitors Amazon S3 Bucket resource access policies
                * Provide alerts regarding bucket shared outside of your account
                * Based on the AWS IAM Access Analyzer
                * Available at no additional cost
            * AWS S3 Access Points
                * Create application-specific access points permitting access to shared datasets with policies tailored to the specific application.
                * Change access point and provide policy against the access point
            * Best Practices
                * Encrypt all objects, set default encryption on bucket
        * RDS
            * Network Isolation
                * Private subnet, specific IP range, Security Group, Network ACLs
            * Database Access Control
                * Native database master user account
                * Capability to create additional user account
                * Otken provided by IAM for DB authentication
            * RDS Service Access Control
                * Specific user/group/role perform through IAM policies
                * Least privilege principle should be used
            * Protection in Transit:
                * use TLS and native encryption clients
                * RDS handles access authentication
            * Protection at Rest:
                * AES 256 encyrption
                * Encryption must be enabled at creation of DB
                * Support Transparent Data Encryption (TDE) for certain DB engines
        * DynamoDB
            * Descriptions
                * Fully Managed, noSQL database
                * Consistent low-latency performance
                * No data storage limits
                * AWS patches DB, manages software, and partitions data
            * Fine-grained access control
                * Able to create database-leve permissions that allow or deny access to items(rows) and attributes (columns) based on the need
            * Protection in Transit:
                * use TLS and native encryption clients
                * Only accepts requests with HMAC-SHA256 signature
            * Protection at Rest:
                * Encryption by dfault via SSE
                * Support client-side encryption
                * Uses AES-256
    * Determine how to protect data after it has been archived
        * Amazon S3 Glacier
            * Description
                * Long-term storage for data archiaval and fast object retrieval
                * Data stored redundantly in multiple devices and AZ
                * Access through public AWS API endpoints via TLS
                * Does not support VPC endpoints unless when used as an Amazon S3 storage tier
                    * VPC endpoint is EC2 communicates with database without traversing IGW or NATGW
                * Glacier Vault Policy is immutable. User has 24 hours to revoke after the policy is applied.
            * Protection
                * Time-based retention
                * MFA authentication supported
                * Immutable policy once locked
                * WORM supported
        * Amazon EBS Volume data deletion
            * wipe clean before reuse
            * Conduct specialized wipe procedure
            * Meets compliance requirements with encryption
        * Amazon S3 Object Deletion
            * Removal of mapping from public name to object starts immediately
            * No remote access to deleted object once mapping is removed
            * Underlying storage is reclaimed by system for reuse

## Day2 <a name="Day2"></a>
* Module 6: Securing Network Communications<a name="securenetwork"></a>
    * Appy seucirty best practices on VPC
        * AWS provides NAT GW or NAT Instance
        * NACL
            * Applies to the subnet level
            * Stateless
            * Rules to deny list or allow list
            * Limit to 20 Rules per inbound or outbound rules
        * Security Group
            * Acts as a virtual FW for instances
            * Stateful Protection
            * Allow ingress and egress rules
            * Configuration is needed to allow communication
            * 50 ingress and 50 egress rules per security group
        * VPC Traffic Mirroring
            * Detect entwork and security anomalies/threats
            * Gain operational insight
            * Implement compliance and security controls
            * Allows real time traffic inspection. Flow log is record of A to B.
            * Use Cases
                * mirror inbound TCP traffic to a single monitoring appliance
                * monitor inbound TCP and UDP traffic to two monitor appliance
                * monitor non-local VPC traffic
    * Secure AWS resources in multiple VPC and AWS accounts
        * Forensics
        * Create an AWS CloudTrail multi-region trail
        * Protect Log information
        * Isolate affected resources
        * Steps
            * Gather Information about the compromised instances
            * Tag instance to quarantine with ec2 create-tags 'Quarantine = Yes'
            * Create snapshot of compromised instance EBS data volume
            * Create copy of compromised volumes and attached to a foresnic instance for analysis
            * Compromised instance can also be accessed for a memory dump
            * Isolate the device from auto scaling group
            * Deregister instance from ALB
            * Isolate instance by placing in separate security group
            * Protect instance from accidental termination with the disableApiTermination attribute
    * Privately connect to other AWS services without traversing the Internet
        * VPC Peering
            * Networking connection between two VPCs that enables you to route traffic between them using private IP addresses.
            * One side of the VPC as requestor. The other side of the VPC as acceptor.
            * Update routing table
            * Transitive connection is prohibited. Must use mesh topology. For example, VPC A peers with VPC B. VPC B peers with VPC C. VPC A cannot talk to VPC C. Use formula (n-1) * n / 2 to obtain number of peering connections, where n is number of VPCs.
            * Transitive connection between corporate network A to VPN gateway VPC B is allowed. VPC B to VPC C peering is established. Corporate network A to VPC C is not supported. Use Transitive Gateway solve the issue.
            * Inter-region VPC Peering costs money.
        * VPC Endpoints
            * Enables connect your VPC to supported AWS services and VPC endpoint services powered by PrivateLink without requiring an internet gateway, NAT device, VPN connection, or AWS Direct Connect connection.
            * Enables instance to privately connect to service without an Internet/Virutal gateway
            * Traffic between your VPC and another service does not leave AWS
            * Interface and gateway endpoints available
            * IAM policies used to grant access to endpoints
            * AWS Privatelink allows customer to access AWS services in a highly available and scalable and keeping all traffic within the AWS network.
                * ENI is created in the subnet that allows to communicate with another VPC, Account.
                * Enable Software-as-a-Service providers to build highly scalable and sercure services on AWS.
            * Multiple endpoints can be configured in a single VPC for different access level
            * Endpoint policies are used to control access to the service
            * Only support for connections to Amazon S3 and DynamoDB
            * Endpoint connections cannot be extended out of a Region or VPC
            * Gateway Endpoint resides inside of the VPC
            * Interface Endpoint resides inside of the subnet
            * Gateway Load Balancer Endpoint resides inside of the target services (S3 and DynamoDB only)
    * Implement ELB device as a point of protection
        * ELB
            * Data-in-transit encryption and decryption
            * Single point of contact and first line of defense
            * End-to-end encryption using TLS for HTTPS
            * Types: ALB, NLB, CLB
            * ALB:
                * Operates at layer 7
                * Routes traffic based on content of the request
                * Providers user authentication
                * Integrates with AWS Certificate Manager (ACM), WAF, and AWS Shield Advanced
            * NLB:
                * Operates at layer 4
                * Load balancing of TCP and UDP packets
                * High-performance applications
                * Integrates with ACM and AWS Shield Advanced
    * Protect data in transit using public and private certificate
        * ACM
            * Provides a single interface to manage both public and private certificates
            * Makes it easy to deploy certificates
            * Protects and store private certificates
            * Minimizes downtime and outages with automatic renewals
            * Considerations
                * HSM
                * IAM Policies for access control
                * Certification Revocation list
                * Generate audit reports

* Module 7: Monitoring and Collecting Logs on AWS<a name="collectLogs"></a>
    * Monitor on AWS
        * AWS CloudWatch
            * Functions:
                * Monitors AWS built-in and custom metrics in real-time
                * Collect log files from services and applications
                * Include events and alarms to send notifications and automatically make changes
            * Use Cases
                * Cloudwatch with EC2 to monitor CPU utilization. Setup CloudWatch alarm if CPU utilization exceeds certain percentage. Cloudwatch notifies Amazon SNS to notify user.
            * CloudWatch Events
                * Events
                    * Resource state change, API events from AWS CloudTrail, Application-Level events, scheduled events
                * Rules
                    * Match incoming events and routes events to one or more targets
        * AWS Config
            * Functions
                * Continuously capture details on all configuration changes associated with your resources
                * Enables compliance monitoring and security analysis
                * Sends notification when changes occur to S3 bucket 
                * AWS Managed Rules vs User Custom Rules
        * AWS Macie
            * Function
                * Recongnzies sensitive data: PII, financials, encryption keys/credentials
                * Protect data stored in Amazon S3 by monitoring resources policies and ACLs
                * Allows for custom-defined data types
                * Provides full API coverage for management
                * Integrates with AWS Organizations
    * Logging on AWS
        * Strategies
            * Keep all logs in centralized respoitory
            * Log as much as you can
            * Keep logs for long-term analysis
        * Amazon CloudWatch Logs
            * Functions:
                * Works with existing system, app, and custom log files
                * Monitors logs in real-time for specific phrases, values, or patterns
                * Provides centralized location for better management
                * Enables interactive query and analysis of collected log data
            * Getting Started
                * Install agent and attach role
                * Monitor with metric filters
                * Access Log Data
            * CloudWatch Logs Insights
                * interactively search and analyze log data in Amazon CloudWatch logs
            * Use Cases
                * Configure CT to deliver logs to CloudWatch
                * Create filter to detect root account usage
                * Create alarm to notify Amazon SNS
                * Test by taking some AWS action with root credentials
                * Verify the event took place
        * Amazon VPC Flow Logs
            * Functions:
                * Sends flow log directly to CloudWatch Logs or Amazon S3
                * Monitor traffic that is reachign your instance
                * Used to troubleshoot network connectivity
            * Customize VPC Flow Log
                * add fields: VPC id, Instance ID, TCP Flags, Traffic Types, Packet-Leve Traffic, AWS Region, AZ id, Sub-location id.
        * Amazon S3 Server Access Logs
            * Tracks request to Amazon S3 bucket
            * Each log record is an individual request
            * Useful in security and access audit
            * Provide insgihts into customer base trends and patterns
            * Records contains: remote ip, requester, operation, request-URI, turn-around time
        * ELB Access Logs
            * Function
                * Detailed information abotu requests sent to ELB
                * Logs are sent to an S3 bucket and stored as compressed files
                * The original cient IP address and port is reported in logs
            * Access Log record contains: client:port, request_processing_time, response_processing_time, request, chosen_cert_arn

* Module 8: Processing Logs on AWS<a name="processLog"></a>
    * Challenges
        * Too much log data to handle manually and keep up with
        * Takes time to move and stage data to be processed
        * Overhead costs in setting up and managing servers/data warehouess
    * Amazon Kinese
        * Functions:
            * Collect, process, analyze streaming data
            * Log Ingestion: Amazon Kinesis Data Streams, Firehoses
            * Log Analysis: Amazon Kinesis Data Analytics
        * Amazon Kinesis Data Streams * Customizable Approach
            * Data producers produces data
            * Data Stream shards reads data records from producer and write data into streams for processing
            * Redshift/S3/DynamoDB process data and may store data in AWS storage services
            * Shard provisioned by customer. Customer can use AWS Streams API to resharding (add or remove shard)
            * Streams data for consumers is available in subseconds
        * Amazon Kinese Data Firehose *Simple
            * Data producers produces data
            * Data can be batched and compressed before loading it into AWS
            * Analyze by Redshift, S3, ES, Splunk
            * Scales on demand
            * Streamed data is sent to AWS storage within at least 60 seconds
        * Encryption
            * Data is encyrpted before being written to Kinesis
            * Works with customer-provided and AWS -provided CMKs
            * Encryption is supported by Kinesis Data Firehose
        * Amazon Kinese Data Analytics
            * Processes and analyzes streaming data in real time using standard SQL. Kinesis Data Analytics enables you to query streaming data or build entire steraming applications using SQL.
    * Amazon Athena
        * Functions
            * Provides interactive query service to analyze data in Amazon S3 using SQL
            * Serverless
            * Cross-region queries are supported
            * No need to load or aggregate data
            * Use Presto(opensource SQL distributed engine) and Apache Hive
        * Getting Started
            * Select a dataset, create a table, query data
        * Data Protection
            * Ability to query encrypted objects in a S3 bucket in the same region
            * Query results may also be encrypted
            * Data is encrypted in transit via TLS and HTTPS by default

* Module 9: Security Considerations: Hybrid Environments<a name="hybridEnv"></a>
    * Connectivity between AWS and On-Prem Options
        * VPN Connectivity
            * Site-to-Site VPN
                * AWS Managed VPN
                    * AWS Virtual Private Gateway
                    * AWS Router
                    * Customer Gateway
                    * IPSec VPN Connection between AWS and Customer
                * Customer VPN (Software VPN)
                    * Customer buys 3rd party to deploy software VPN in the subnet
                    * AWS Interget Gateway
                    * IPSec VPN Connection
                    * Customer Gateway
            * Client VPN
                * Customer uses OpenVPN application to connect to AWS Client VPN endpoint
                * AWS Client VPN Endpoint
        * AWS Direct Connect
            * AWS Direct Connect Setup
                * Private virtual interface:
                    * AWS Virtual Private Gateway > Direct Connect Endpoint > Router > Customer Gateway
                * Public virtual interface:
                    * S3 / Glacier > AWS Cage > Customer/Parner Cage > Customer Gateway
            * Use cases
                * consistent and secured connection for workign with large dataset
                * Improve latency for real-time data feeds
                * Meet compliance requirements with a private link for hybrid
                * Combine AWS Direct Connection with IPSecVPN Connection
            * AWS Direct Connect Gateway
                * Connect VPC in any AWS region via private virtual interfaces.
                * Support BGP is required
            * Bypass internet
        * AWS Transit Gateway
            * Enables customers to connect VPC and on-prem networks to a single gateway. Acts as distributed router. Leaverage hyperplane architecture.
            * Connections
                * VPC B > AWS Transit Gateway > IPSec VPN Connection > Customer Gateway
                * VPC B > AWS Transit Gateway > VPC A
            * Enables 5000 VPC can be connected to TGW
            * Transit Gateway can provide multiple interfaces that connect to different customer site.
            * Scales elastically based on network traffic volume
            * Attaches to one or more VPC, VPN connections, or AWS Direct Connect Gateways
            * Commonly used to isolate VPCs

* Module 10: Out-Of-Region Protection<a name="oorPro"></a>
    * DoS Threats
        * Layer 7: DNS Flood, Slow Loris, HTTP Flood
        * Layer 3 and 4: UDP Reflection, SYN Flood, ICMP Flood
        * Mitigation:
            * Security Group, NACL, WAF, Route 53, CloudFront
            * Mitigation Appraoches
                * Minimize attack surface
                    * Keep important instance behind NAT
                    * Implement ELB/ALB
                * Safeguard exposed resources
                * Benchmark normal behavior
                * Scale and Absorb attack (Last Resort)
    * DDoS Resiliency
        * Protect Application via AWS ELB, AWS WAF, AWS Firewall Manager, AWS Shield, Amazon CloudFront, Amazon Route 53
        * Amazon Route 53
            * Functions
                * High available & scalable DNS web service.
                * Health Checking
                * Fault Tolerance
                * Anomaly Detection
                * Traffic Flow
            * Anycast Striping: each DNS request is served by the most optimal location
            * Shuffle Sharding: name servers are randomly selected across separate zones
        * AWS WAF
            * Functions
                * Detect and block web requests
                * Web traffic filtering
                * Real-time metrics
                * Application Layer protection
                * Secure and protect REST APIs
            * Create Rules (allow, block, monitor) based on conditions. Conditions based on IP Address, HTTP header, HTTP Body, XSS
            * Pay by the Web ACL
        * Amazon CloudFront
            * Functions
                * Offers CDN for caching capability to deliver data, video, app, and APIs.
                * Attack isolation with edge locations
                * Application and network level protection with AWS Shield and AWS WAF
                * Encryption for sensitive data
            * How it works
                * HTTP/HTTPS:
                    * live events in real time
                    * media files, web page
                    * media file streaming
            * Restrict access at the origin
                * Origin access identities for S3 bucket
                * User access objects via CloudFron URL instead of S3 URL
                * Update security group of origin instance to only allow CloudFront traffic
            * Restrict access at the edge
                * Signed URL or signed cookies for selective file download/streaming or access control of multiple files
            * Field-level encryption for sensitive data: protect sensitive data from being accessed by unauthorized services within AWS
            * CloudFront access logs
        * AWS Shield
            * Function
                * Adaptive protection on level 3, 4
            * Advanced Option provides
                * 24/7 support from DDoS Response Team
                * Expanded DDoS protection
                * Cost effcient
        * AWS Firewall Manager
            * Function
                * Setup WAF rule and confugre SG across multiple accounts and resources
                * Auto protect resources taht are added to your account
                * Only availabel for accounts that are AWS Organization members
        * Where to Start?
            * WAF: start here for granular control over the protection that is added to your resources
            * FW Manager: use AWS WAF across accounts and to automate protection of new resources
            * Shield: use only for high-visibilit websites or prone to frequent DDoS attacks
## Day3 <a name="Day3"></a>

* Module 11: Security Considerations for Serverless Environements<a name="#severless"></a>
    * Serverless Architecture consists of Route53, CloudFront, API Gateway, Lambda, DynamoDB | Aurora, Cognito, S3, Kinesis, SNS, SQS, LightSail
    * Use Lambda function if the code can be run within 15 min
    * Amazon Cognito and Web Identity Providers
        * AWS Cognito
            * Provide access control and authentication for web/mobile app
            * Data at-rest and in-transit encryption
            * Log in via social identity providers
            * Supports MFA and SAML
            * Fully Managed Services
            * HIPPA-eligible and compliant with PCI DSS, SOC, ISO/EIC 27001, ISO/EIC 27017, ISO/EIC 27018, and ISO 9001
            * User Pools
                * User directory in Amazon Cognito. App users can sign in through a user pool or federated through a third-party identity provider (FB, GOOGLE, OpenID Connect, and SAML IdPs)
                * Functions
                    * Sign-up and sign-in services
                    * Built-in customizable login web UI
                    * Control who can access your API
                    * Compromised credentials check
                    * Phone and email verification
                    * Adaptive authentication
            * Identity Pools
                * Integrate third-party identity providers (FB, GOOGLE, OpenID Connect, and SAML IdPs)
    * API Security with Amazon API Gateway
        * Amazon API Gateway
            * "Front Door" for app
            * Protect against traffic spikes with throttling
            * WAF integration
            * Authorization and access control
            * Visually monitor calls with Cloudwatch
            * Features
                * Support HTTPS
                * ARNs can be referenced in IAM policies for grainular control
                * Support transaction rate limits via caching
                * DDoS attack mitigation
    * AWS Lambda
        * Function
            * Securely access other AWS services
            * IAM roles used to provide permissions
            * Leverage security groups and NACLs
            * Support environmental variable encryption via AWS KMS
        * Invoke Function
            * Invocation Types: Synchrnous vs Asynchronous
            * A event source (push model): event occurs and signals Lambda function to start running
            * AWS Lambda (pull model): lambda poll dynamodb multiple times per second and invoke lambda function with the batch of updates that have been published to the stream.
            * Direct invocation (Request-response model)
        * Resource-based policies for invoking functions
            * add a policy to a Lambda function grant permission for it to be invoked
            * Add multiple statemetn in the policy to grant access to multiple accounts
            * Specify the service invoking the function as the principal and `lambda:InvokeFunction` as the action
        * Role for function exectuion
            * Lambda function + Execution Role = Allow actoin
            * IAM Role with (1) Trust Policy allow Lambda to assume role (2) IAM Policy permissions
        * Monitor and Log functions
            * Invocations: number of times a function is invoked
            * Errors: number of invocation fails
            * Duration: function running time from start to stop
            * Throttles: number of invocation attempts that were throttled due to invocation rate exceeds the limit

* Module 12: Threat Detection and Investigation<a name="#threatdetect"></a>
    * AWS GuardDuty
        * Functions
            * intelligent threat detection and continuous monitoring to protect AWS accounts and workloads
                * Finds recon, account, and workload anomalies
            * Identifies suspected attackers through integrated threat intelligence feeds from AWS, CrowdStrike, and Proofpoint
            * Uses ML to detect anomalies
        * Detection Categories
            * Recon
                * Known malicious IP (Commercial), Unusual API activity (CloudTrail), Port Scanning (VPC Flow), Unusual Ports
            * Instance Compromise
                * RDP brute force, Unusual Traffic Volume, Bitcoin Activity, Tor Network, DNS Exfiltration (DNS Log)
            * Account Compromise
                * Anonmyizing proxy, Unusual region launch, disabling CloudTrail, Unusual instance or infrastructure launch
        * Getting Started
            * Enable GD on all accounts
            * Continuously Analyze data (CT, VPC Flow, DNS). If customer doesn't have those logs configured, GuardDuty will analyze the logs under the hood.
            * Intelligently detect threat
            * Take action with detailed finding
        * Detecting Threats
            * GD Consumes feed from various sources:
                * AWS Security
                * Commercial feeds from Prrofpoint and CrowdStrike
                * Open source feeds
                * Customer-provided threat intel
                * Site hosting malware and hacker tool
            * Algorithm detect unusual behavior (7 and 14 days). Time-based behavior
                * Inspect signal patterns for signatures
                * Profiling normal and looking at deviations
                * ML Classifier
        * Pricing is based on CT, VPC Flow, and DNS logs volume.
    * AWS Security Hub for Threat Prioritization
        * Functions
            * Fully managed service
            * Consolidates security findings across accounts, services, and third-party products
            * Collects and prioritizes findings based on your security and compliance requirements
            * Aggregate GuardDity, Macie, Inspector, FW Manager, IAM Access Analyzer
        * Getting Started
            * Enable Security Hub for all of your accounts
            * Continously aggregate and prioritize findings
            * Conduct automated compliance scans and checks
            * Take actions
        * AWS Security Hub Insights
            * Findings are correlated and grouped for prioritization
            * Compliance Checks, CIS Benchmark Check
        * Threat Response Automation
            * Security Hub > Security Findings as Custom Events > Amazon CloudWatch Events Rule > Identify finding by color code and invoke Amazon SNS or invoke Lambda Functions
    * AWS Detective
        * Functions:
            * Fully managed services
            * Allow quick investigation of root causes via prebuilt data aggregations
            * Provide custom and interactive visualization for analysis
        * Getting Started
            * Enable Amazon Detective for all accounts
            * Continuously aggregate and process findings
            * Investigate findings from AWS services and partner
            * Get context and drill down to specific
        * Processing findings
            * CT, GD, VPC Flow Log processed by Amazon Detective. AWS Detective updates behavior graph and populates AWS Detective Console. Behavior Graph is analyzed by AWS Detective Analytics
        * Investigate Findings
            * Integrate GD and Security Hub
            * View associated resource activity with each GD findings to determine next steps
            * Also directly investigate the following extracted entities: AWS account, IP address, AWS roles | users, User agent, EC2 instances

* Module 13: Secrets Management on AWS<a name="#secret"></a>
    * Encryption
        * Symmetric: AES, RC4, DES
            * Length: 128, 256 bits key
        * Asymmetric: RSA, DH ECG
            * Length: 1024, 2048 bits key
    * AWS KMS
        * Functions:
            * Managed key storage and management, and data encryption
            * Two-tiered key hiearchy using envelope encryption
            * Centrally manage and secure keys
            * Determine who can use keys with usage policies
            * Multi-tenant
        * Envelope Encryption Example
            * ![Envelope Encryption](https://www.control-alt-del.org/images/envelope-encryption.png)
        * Functionality
            * Create master keys with a unique alias and description. Master key resides in AWS.
                * Master Key has 4KB only
            * Automatically rotate master keys
                * AWS Managed (1/3 years)
                * Customer Managed (1 year)
            * Disable or delete keys (Customer Managed)
            * Audit use of keys via AWS CloudTrail
            * Import Key
        * Key Protection
            * Policies
                * Resource-based permissions
                * Similar syntax to IAM policies
                * Specifies who can manage a key and who can encrypt/decrpt
            * Grants
                * Temporary or more granular permissions
                * Programmatically delegate CMKs
                * Use to allow access
        * Import Keys
            * Use customer key with AWS services and your own applications
            * Have greater control over the lifecycle and durability of your keys
            * Meet compliance requirements to generate and store copies of keys outside of AWS
        * Rotate Keys
            * Create new Customer Master Key (CMK) and point alias to new key (assumes aliases are used)
                * CMK is schematric representation of the master key.
                * Schematric representation: key id, creation date, state, key-material
            * Update key policy of old key so that users cannot use that key
            * Disable old CMK
        * CMK
            * AWS Owned CMK: AWS managed, customer cannot see
            * AWS Managed CMK: customer can see these keys. It's under AWS managed keys
            * Customer Managed CMK: customer create, manage, control the keys
            * Multiple tenant uses the same HSM
    * AWS Cloud Hardware Security Module
        * Functions
            * Securely generate and store keys in a tamper-resistant hardware device.
            * Comply with strict key amangement requirements and compliance
            * Keys are managed only by the customer
            * FIPS 140-2 Level 3
        * Architecture
            * Up to 32 HSM per cluster.
            * Add/remove HSM to meet demand
            * Pay only the provisioned instance
            * Customer manage the cluster
            * Single tenant
        * Separation of duties
            * AWS manage the appliance
            * Customer control key and crypto operation
    * AWS Secret Manager
        * Best Practices
            * Safely and securely store secrets in a central repository
            * Audit log for the use and misuse of secrets
            * Secrets rotation on a regular schedule
            * Access control of secrets
        * Functions
            * A secure and scalable method for managing access to secrets
            * A way to meet regulatory and compliance requirements
            * Rotates secrets safely without breaking applications
            * Audits and monitors the lifecycle of secrets
            * Avoid putting secrets in code or config files
        * Rotating Secrets
            * Function contacts DB for new credential
            * New credentials are stored by Secret Manager with AWSPENDING label
            * New crednetials are tested
            * New credentials are made default with AWSCURRENT label

* Module 14: Automation and Security by Design<a name="#autosec"></a>
    *  4 Phases Approach
        * Understand the requirements
        * Build a secure environment
        * Enforce the use of the templates (Use Service Catalog) to enforce secure environment
        * Perform validation activities
            * Use rules defined in your secure tempaltes as an audit guide
    * [Reference](https://d1.awsstatic.com/whitepapers/compliance/Intro_to_Security_by_Design.pdf)
    * Design: Access Control for User, Reliable Operation of Controls, Continuous and real-time auditing, compliance as code
    * AWS CloudFormation (Infrastructure as code)
        * Provisions AWS Resources in a predictable, repeatable, and automated fashion
        * Quickly replicates your infrastructure across regions
        * Controls and tracks changes to your infrastructure
        * Uses templates and stacks to create and provision resources
        * Uses JSON or YAML
        * Use Cases
            * Use Modular Design for IAM configuration, VPC, Application architecture, Application
        * Security considerations and best practices
            * Use AWS IAM to control access
            * Catalog Administrators for managing and organizing products into portfolios
            * Use dynamic references instead of embedding credentials in your template
            * Use CloudFormation drift detection to validate configuration change
            * Use stack termination protection, DeletionPolicy, and stack policies to avoid unwatned updates and deletions
    * AWS Service Catalog
        * Functions:
            * Enables end users to deploy approved and secure services using self-service
            * Helps achieve consistent govenance and meet compliance requirements
            * Ideal for MSO/MSPs
        * Components
            * Portfolios
            * Product
            * Constraints
            * Versioning
            * Stack
        * Monitoring and tracking products
            * AWS CloudTrail: record and track access to stacks and their resources
            * AWS Config: record and track change events as stacks are being changed
            * AWS CloudWatch: monitor and notify on health of stacks, their changes, and access

* Module 15: Account Management and Provisioning on AWS<a name="#acctnmngt"></a>
    * Multiple AWS Accounts Use Case
        * Group resources for compliance requirements
        * Improve security posture with a logical boundary
        * Limit blast radius in case of unauthorized access
        * Efficiently manage user access to different environment
    * AWS Organizations
        * Functions
            * Offers policy-based central management for multiple AWS accounts
            * Organize AWS accoutns into organization units
            * Manage policies across accounts
            * Automate creation of new accounts through API
            * Consolidate Billing and All Feature modes
        * Security Benefits
            * Enable logging for all accounts
            * Collect data across all accounts for auditing
            * Centrally create, modify, and manage web application firewalls
            * Allow organization-wide notification publishing
        * Getting Started
            * Create an organization
            * Create OU
            * Add or create AWS Account
            * Create and assign Service Control Policies
    * AWS Control Tower
        * Functions
            * Automate the setup of multiple accounts based on best practices in a landing zone
            * Applies pre-packged guardrails that provide ongoing governance
            * Provides an integrated dashboard to view your landing zone, reports, and guardrails applied to your environment
        * What is configured in a landing zone
            * Multi-account environment
            * Identity management and federated access
            * AWS CloudTrail configured in each account
            * AWS Config is enabeld and Config Rules used for monitoring
            * Network Settings
            * Notification
            * GuardDuty enabled
            * Mandatory guardrails are always enforced. Strongly recommended guardrails are designed to enforce some common best practices for well-architected, multi-account environment
        * Control Tower or Organization or Landing Zone
            * Choose Control Tower
                * Automated deployment of a multi-account environment according to AWS best practices
                * Build a new AWS environment or are starting new cloud initiative
                * A self-service experience to set up a new pre-configured environment with guardrails
                * An interactive user interface for visibiltiy and to simplify management
            * Choose OU
                * Define own custom multi-account environment with advanced management capabilities
                * Create granular SCP that centrally the use of AWS services and resources across multiple accounts
            * Choose Landing Zone
                * More customization option and to setup a configurable landing zone
                * Change management thorugh a code deployment and configuration pipeline
        * Federated User Access
            * Federated User
                * External users have permisson to use AWS resources in your account
                * Long-term security credentials are not distributed
            * AWS SSO
                * Functions
                    * Provides an AWS SSO user portal
                    * Built-in integrations with business cloud applications
                    * Built-in directory for user and group management
                    * Integration with on-premises Active Directory and AWS Organizations
                    * Centralized permissions management and auditing
                * Getting Started
                    * Enable SSO
                    * Connect to identities
                    * Grant SSO access
                    * Setup SSO to cloud applications
                * AWS SSO User Portal
                    * User portal displays accounts and cloud applications the user can access
            * AWS Directory Service
                * Functions
                    * Run directories in AWS Cloud
                    * Ability to connect AWS resources to on-premises Active Directory
                    * Reduces managment tasks
                    * Automatic monitoring for failed domain controllers
                * Use AD in AWS cloud
                    * Simple AD: low scale, low-cost basic AD capability (Linux Samba not offering AD feature)
                    * AD Connector: On-premises user require access to AWS services via AD
                    * AWS Managed MS AD: MSFT AD is needed in AWS cloud
                * AWS Managed MSFT AD use case:
                    * AWS handles patching and software update
                    * Daily snapshots are automtated
                    * Capability to add more domain controllers
                    * Encryption via TLS
    * Lab Ref: https://globalknowledge.qwiklabs.com
* Reference
    * [exam](https://aws.amazon.com/certification/certified-security-specialty/)
    * [mindmap](https://drive.google.com/drive/folders/1gqOstEiQ0XG91xohCSS9q-A1Vf9pZ2P5?usp=sharing)
    * Instructor: fayaz.khan@globalknowledge.ae


