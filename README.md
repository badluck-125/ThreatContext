#ThreatContext
Local LLM application for CVE -> IoC pipeline

## Personnal project, not for production use(yet)
This project rely on a 3-tier + LLM architecture

### RoadMap
Features OK
* ExploitDB input script to feed its data to ThreatContext database
* DockerCompose and DockerFile infrastructure layer

Features to add
1. API script to input log sample data in threatcontext-db for tab_sample
2. Build the RAG application to retrieve IoC based on exploit + log samples
2. Web interface to input/consult exploit+cve data in threatcontext-db for tab_cve and tab_exploit
3. Web interface to input/consult log sample data in threatcontext-db for tab_sample
3. Web interface to prompt threatcontext

