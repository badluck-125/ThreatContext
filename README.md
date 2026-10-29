#ThreatContext
Local LLM application for CVE -> IoC pipeline

## Personnal project, not for production use(yet)
This project rely on a 3-tier + LLM architecture

### RoadMap
Features OK
* ExploitDB input script to feed its data to ThreatContext database
* DockerCompose and DockerFile infrastructure layer
* API script to input log sample data in threatcontext-db for tab_sample
* RAG application to guess IoC based on exploit and log samples

Features to add
1. Web interface to input/consult exploit+cve data in threatcontext-db for tab_cve and tab_exploit
2. Web interface to input/consult log sample data in threatcontext-db for tab_sample
3. Web interface to prompt threatcontext

