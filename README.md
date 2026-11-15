# ThreatContext

## Installation

This is for a simple docker based installation
```bash
git clone https://github.com/badluck-125/ThreatContext.git
cd ThreatContext
docker compose up -d
```

If you want to input data from exploitDB, run the input script.
You need to install clone the exploitDB gitlab repo first.
https://gitlab.com/exploit-database/exploitdb

```bash
bash input_script/input_exploitDB.bash
```
You can then connect to the presentation tier using this url
http://127.0.0.1:8080/

Or you can connect to the application tier directly using this url
http://127.0.0.1:8090/
