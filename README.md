# 🚀 Cloud-Native SIEM with MITRE ATT&CK Mapping

A production-ready Security Information and Event Management (SIEM) system built on AWS that automatically maps security events to the MITRE ATT&CK framework, provides threat intelligence enrichment, and enables automated incident response.

## 📋 Features

### 🎯 Core Capabilities
- **Real-time Security Event Processing**: Process events from AWS Security Hub, GuardDuty, and CloudTrail
- **MITRE ATT&CK Framework Mapping**: Automatically map security findings to MITRE tactics and techniques
- **Threat Intelligence Integration**: Enrich events with OpenCTI, VirusTotal, and AbuseIPDB data
- **Automated Incident Response**: Execute playbooks based on severity and MITRE techniques
- **Interactive Dashboards**: Kibana dashboards for visualization and analysis
- **Multi-source Log Collection**: Support for AWS native security services

### 🔧 Technical Features
- **Serverless Architecture**: Built with AWS Lambda, EventBridge, and S3
- **Infrastructure as Code**: Complete Terraform deployment
- **Containerized Services**: Elasticsearch, Kibana, OpenCTI via Docker Compose
- **Automated Deployment**: One-command deployment script
- **Cost Optimized**: Pay-per-use serverless components

## 🏗️ Architecture

```mermaid
graph TB
    A[AWS Security Services] --> B[EventBridge]
    B --> C[Lambda Processor]
    C --> D{Enrich & Analyze}
    D --> E[Elasticsearch]
    D --> F[OpenCTI]
    D --> G[Response Actions]
    E --> H[Kibana Dashboard]
    G --> I[AWS Services]
    F --> C
    
    subgraph "AWS Cloud"
        B
        C
        G
        I
    end
    
    subgraph "Local/Container"
        E
        F
        H
    end
