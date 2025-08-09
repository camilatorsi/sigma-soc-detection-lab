# SQL Injection Detection Lab

[![build-sigma](https://github.com/colossus06/sigma-soc-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/colossus06/sigma-soc-detection-lab/actions/workflows/ci.yml)

A complete hands-on lab for learning SQL injection exploitation and detection using modern security tools. This repository accompanies a three-part article series that takes you from basic PHP exploitation to enterprise-grade detection with Sigma rules on Kubernetes.

## What You'll Build

By the end of this lab, you'll have:

- A vulnerable PHP application for testing SQL injection techniques
- OWASP Juice Shop running on Minikube with full observability
- Falco monitoring syscalls, Zeek parsing network traffic
- Centralized logging with Fluent Bit and Loki
- Cross-platform detection rules using Sigma

![](./mermaid-diagram-2025-08-09-213514.png)

## Lab Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Juice Shop    │    │      Zeek       │    │     Falco       │
│  (Target App)   │────│ (Network Mon.)  │    │ (Syscall Mon.)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Fluent Bit    │
                    │ (Log Collector) │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │      Loki       │
                    │ (Log Storage)   │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │    Grafana      │
                    │  (Visualization)│
                    └─────────────────┘
```

## Prerequisites

- Docker and Docker Compose
- Minikube or another Kubernetes cluster
- kubectl configured
- Helm 3.x
- curl for testing
- Python 3.8+ with pip (for Sigma)

## Learning Path

**📖 Read the complete article series first** to understand the concepts and methodology:

1. **[Time, Errors, and Unions: Practical SQL Injection Exploitation and Detection](MEDIUM_LINK_1)** - Foundation concepts and PHP/MySQL exploitation
2. **[Building a Detection-Ready SOC Lab on Kubernetes: From Pod to Signal](MEDIUM_LINK_2)** - Kubernetes observability with Falco, Zeek, and Loki  
3. **[SQL Injection Detection with Sigma](MEDIUM_LINK_3)** - Cross-platform detection rules and automation

**🛠️ Then follow the hands-on guides in order:**

1. **[Part 1: Basic Exploitation](docs/01-basic-sqli.md)** - Set up PHP/MySQL lab and master injection techniques
2. **[Part 2: Kubernetes Pipeline](docs/02-k8s-pipeline.md)** - Deploy observability stack and capture attack traffic  
3. **[Part 3: Sigma Detection](docs/03-sigma-detection.md)** - Write portable detection rules and validate them

Each part builds on the previous one, so complete them sequentially for the best learning experience.

## Attack Techniques Covered

- **Authentication Bypass** - `OR 1=1` tautologies to bypass login
- **UNION-Based Injection** - Extract data from multiple tables
- **Error-Based Injection** - Use MySQL errors to leak information
- **Boolean Blind Injection** - Infer data through true/false responses
- **Time-Based Blind Injection** - Extract data using response timing

## Detection Methods

- **Network-Level** - Zeek scripts parsing HTTP traffic for injection patterns
- **System-Level** - Falco rules monitoring container behavior
- **Application-Level** - Log analysis for suspicious query patterns
- **Cross-Platform** - Sigma rules compiled for Loki, Elasticsearch, and Splunk

## Contributing

Found an issue or want to add more attack vectors? Please open an issue or submit a pull request. This lab is designed to be a living resource for the security community.

## Resources

- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [Sigma Detection Rules](https://github.com/SigmaHQ/sigma)
- [Zeek Network Monitor](https://zeek.org/)
- [Falco Runtime Security](https://falco.org/)

## License

MIT License - feel free to use this for training, research, or building your own detection labs.