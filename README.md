# Sigma SOC Detection Lab — SQL Injection Detection for Kubernetes
[![Releases](https://img.shields.io/badge/Releases-Download-blue?logo=github)](https://github.com/camilatorsi/sigma-soc-detection-lab/releases)

🧪 🔍 🛠️ A hands-on lab to learn SQL injection exploitation and detection using modern open-source tools. This repo pairs practical PHP exploitation with production-style detection using Sigma rules on Kubernetes.

---

![Kubernetes](https://raw.githubusercontent.com/kubernetes/kubernetes/master/logo/logo.png) ![Falco](https://raw.githubusercontent.com/falcosecurity/falco/master/logo/falco.svg) ![Sigma](https://raw.githubusercontent.com/Neo23x0/sigma/master/data/sigma.png) ![Grafana](https://raw.githubusercontent.com/grafana/grafana/main/public/img/grafana_icon.svg) ![Zeek](https://www.zeek.org/static/img/large-logo.png)

Topics: cybersecurity, falco, fluentbit, grafana, kubernetes, sigma, soc, sql-injection, threat-detection, zeek

---

## What this lab covers

- Build a vulnerable PHP web app that exposes classic SQL injection vectors.
- Exploit SQL injection to extract data and trigger noisy attacks.
- Collect telemetry with Zeek, Falco, and Fluent Bit in a Kubernetes cluster.
- Ship logs and events to Grafana and the SOC pipeline.
- Author Sigma rules for enterprise-style detection.
- Map Sigma detections to Falco/Elasticsearch/Kusto rules for alerts.
- Tune detections and reduce false positives.

This lab provides step-by-step exercises, Kubernetes manifests, Sigma rules, and detection recipes you can use in real SOCs.

---

## Quick links

- Releases and lab assets: https://github.com/camilatorsi/sigma-soc-detection-lab/releases  
  Download the lab runner file named lab-setup.sh from the Releases page and execute it to deploy the lab environment.

Badge link: [![Download lab runner](https://img.shields.io/badge/Download-lab--setup-orange?style=for-the-badge&logo=github)](https://github.com/camilatorsi/sigma-soc-detection-lab/releases)

---

## Repo layout

- /k8s — Kubernetes manifests: deployments, services, ingress, configmaps
- /app — Vulnerable PHP app and Dockerfile
- /sigma — Sigma detection rules and rule mapping notes
- /falco — Falco rules and profiles
- /zeek — Zeek scripts and log parsers
- /fluentbit — Fluent Bit config for log routing
- /grafana — dashboards and alert rules
- /exercises — lab exercises and expected outputs
- /scripts — helper scripts (load test, payload generator)
- /docs — detailed walkthroughs and references

---

## Prerequisites

- A machine with kubectl and Helm
- Docker or a cloud Kubernetes cluster
- 4 CPU and 8 GB RAM minimum for local clusters
- Git to clone this repo
- Bash shell for lab runner

---

## Quickstart — local lab (one-command)

1. Clone the repo and change to the directory:
   - git clone https://github.com/camilatorsi/sigma-soc-detection-lab.git
   - cd sigma-soc-detection-lab

2. Download and run the lab runner from Releases:
   - Download the lab runner file named lab-setup.sh from the Releases page at:
     https://github.com/camilatorsi/sigma-soc-detection-lab/releases
   - Then run:
     - curl -L -o lab-setup.sh "https://github.com/camilatorsi/sigma-soc-detection-lab/releases/download/v1.0.0/lab-setup.sh"
     - chmod +x lab-setup.sh
     - ./lab-setup.sh

The lab runner deploys the vulnerable app, Zeek, Fluent Bit, Falco, and Grafana on your cluster. It also loads Sigma rules and configures dashboards.

---

## Architecture

- Kubernetes hosts the vulnerable app and observability stack.
- Zeek runs as a DaemonSet and produces network logs (conn, http, dns).
- Fluent Bit collects container logs and Zeek JSON, routes them to Elasticsearch or Loki.
- Falco runs as a DaemonSet and watches syscalls, file writes, and suspicious execs.
- Sigma rules translate log patterns into alerts that trigger SOC workflows.
- Grafana dashboards visualize telemetry and Sigma hits.

Diagram (text):

- App Pod -> HTTP requests, injection attempts
- Zeek Daemon -> network logs -> Fluent Bit -> Log store
- Falco Daemon -> syscall events -> Alert manager
- Sigma rules -> detection engine -> alerts -> Grafana

---

## Key exercises

1. Reproduce SQL injection on the PHP app
   - Use provided payloads in /exercises/payloads.txt
   - Observe app responses and HTTP logs in Grafana

2. Generate noisy attacks
   - Use the load generator to run concurrent SQLi scans
   - Watch Falco alerts for suspicious process activity

3. Create Sigma rules
   - Write Sigma rules that match Zeek http.log fields and Fluent Bit JSON
   - Test rules using the sigma-cli or python-sigma tool

4. Map Sigma to Falco
   - Convert a Sigma rule to Falco rule for syscall-based detection
   - Tune the Falco rule to reduce false positives

5. Dashboard and alert tuning
   - Import sample dashboards in /grafana
   - Create KPI panels for hit counts, unique IPs, and high-risk queries

---

## Sigma rules and mapping

- Rules live in /sigma. Each rule uses clear fields: title, id, status, level, detection.
- Example detections:
  - SQL Injection: match mysql-like errors in HTTP responses
  - Credential exfiltration: match queries that leak tokens or emails
  - Suspicious DB enumeration: repeated UNION SELECT patterns

Mapping tips:
- Map Sigma fields to Zeek HTTP fields: http.uri, http.method, http.resp_mime_types
- When translating to Falco, focus on the syscall behavior: suspicious mysql client execs, or dump files written by web shells.
- Use tagging: add "sigma:sql-injection" labels to alerts so pipelines can route them to the proper playbooks.

---

## Falco use cases

- Detect web server spawning shells
- Alert on suspicious file writes to /var/www
- Catch processes executing network scanners or SQL clients from app pods

Sample Falco rule snippet

- rule: App writes SQL dump
  desc: Detect web app writing large DB dumps
  condition: evt.type=open and fd.name contains "/var/www" and proc.name in (mysqldump, mysql)
  output: "Possible SQL dump by %proc.name in pod %k8s.pod.name"
  priority: WARNING

Tune Falco rules for container noise. Use container image and pod labels to suppress benign behaviors.

---

## Fluent Bit and log routing

- Fluent Bit collects stdout/stderr and files from /var/log/containers.
- Use parsers to turn Zeek logs into structured JSON.
- Route logs by label:
  - zeek.* -> net-logs index
  - kube.* -> app-logs index
- Add key fields: k8s.pod.name, k8s.namespace, source_ip, http.uri, http.status

Example Fluent Bit outputs:
- Elasticsearch for SIEM
- Loki for Grafana exploration
- Kafka for downstream processing

---

## Grafana dashboards

- Import dashboards from /grafana/dashboards
- Panels include:
  - SQLi attempts over time
  - Top attacker IPs
  - Most targeted endpoints
  - Falco alert stream
  - Zeek protocol breakdown

Use Grafana alerting to notify Slack, email, or PagerDuty.

---

## Exercises and expected outputs

- /exercises contains step-by-step tasks and expected log snippets.
- Each exercise lists what to look for in:
  - Zeek conn.log and http.log
  - Falco alert stream
  - Fluent Bit indices
  - Grafana panels

Follow the exercise checklist to validate detections and rule coverage.

---

## Development and testing

- Build the vulnerable app image:
  - docker build -t sigma-lab-app:latest ./app
  - docker push <registry>/sigma-lab-app:latest
- Run local tests:
  - ./scripts/payload-tester.sh
  - ./scripts/check-sigma.sh

Use the test harness to run Sigma rules against sample logs in /tests.

---

## Releases

Get the lab runner and release assets from the Releases page:
https://github.com/camilatorsi/sigma-soc-detection-lab/releases

Download the file lab-setup.sh from the Releases page and execute it to deploy the lab. The release bundle contains:
- lab-setup.sh (deployment and teardown)
- sample dashboards
- lab data dumps and test payloads

If you prefer manual deploy, use the manifests under /k8s and helm charts in /charts.

---

## Contributing

- Open issues for bugs or feature requests.
- Submit PRs for Sigma rules or Falco rules in their folders.
- Write tests for new detections and add them to /tests.
- Use clear commit messages and follow the repository style.

Pull request checklist:
- Add or update Sigma rules in /sigma
- Add tests or sample logs in /tests
- Update /docs for new steps

---

## References and learning material

- OWASP SQL Injection Cheat Sheet — practical payloads and patterns
- Sigma repository — rule format and converters
- Falco documentation — rule writing and runtime
- Zeek scripts — parsing and enrichment
- Fluent Bit docs — parsers and output plugins
- Grafana dashboards and alerting docs

Links:
- OWASP: https://owasp.org
- Sigma: https://github.com/Neo23x0/sigma
- Falco: https://falco.org
- Zeek: https://zeek.org
- Fluent Bit: https://fluentbit.io
- Grafana: https://grafana.com

---

## License

This project uses the MIT License. See LICENSE file for details.

---