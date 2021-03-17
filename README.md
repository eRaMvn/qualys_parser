# `qualys_parser`

qualys_parser is a CLI tool that parses the csv report from Qualys and gives quick result

The tool is only tested on scanning report of ubuntu machines

## Installing

`git clone https://github.com/eRaMvn/qualys_parser.git`

Build executable

```bash
#!/bin/bash
go build
```

Or you can grab one of the executables under `Releases`

## Example Commands

The following examples were executed on the `samples/reports.csv` file

1. Generate a report of all vulnerable packages found along with where the packages can be found

`
qualys_parser -i report.csv
`

Sample output:

```json
{
	"OpenSSH_7.2p2": {
		"csv_title": "OpenSSH Information Disclosure Vulnerability",
		"severity": "Medium",
		"solution": "OpenSSH team committed a partial mitigation of this issue which is included in openssh 8.4. \nRefer to OpenSSH 8.4 (https://www.openssh.com/) for details.",
		"count": 1,
		"ip_list": ["172.30.1.6"]
	},
	"git-man": {
		"csv_title": "Ubuntu Security Notification for Git Vulnerabilities (USN-4220-1)",
		"severity": "Medium",
		"solution": "Refer to Ubuntu advisory USN-4220-1 (https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-December/005244.html)...",
		"count": 2,
		"ip_list": ["172.30.1.1", "172.30.1.2"]
	},
	"linux-image-aws": {
		"csv_title": "Ubuntu Security Notification for Linux, Linux-aws, Linux-kvm, Linux-raspi2, Linux-snapdragon (USN-4211-1)",
		"severity": "Medium",
		"solution": "Refer to Ubuntu advisory USN-4211-1 (https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-December/005229.html) ",
		"count": 3,
		"ip_list": ["172.30.1.3", "172.30.1.4", "172.30.1.5"]
	},
	"linux-libc-dev": {
		"csv_title": "Ubuntu Security Notification for Linux, Linux-aws, Linux-kvm, Linux-raspi2, Linux-snapdragon (USN-4211-1)",
		"severity": "Medium",
		"solution": "Refer to Ubuntu advisory USN-4211-1 (https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-December/005229.html)",
		"count": 3,
		"ip_list": ["172.30.1.3", "172.30.1.4", "172.30.1.5"]
	}
}
```

2. Generate a report of all vulnerable packages found along with where the packages can be found but with more details

`
qualys_parser -i report.csv -d
`

Sample output:

```json

{
	"OpenSSH_7.2p2 | Ubuntu-4ubuntu2.10, | OpenSSL": {
		"csv_title": "OpenSSH Information Disclosure Vulnerability",
		"severity": "Medium",
		"solution": "OpenSSH team committed a partial mitigation of this issue which is included in openssh 8.4. \nRefer to OpenSSH 8.4 (https://www.openssh.com/) for details.",
		"count": 1,
		"ip_list": ["10.235.110.8"]
	}
}
```

3. Generate a report of all ips with vulnerable packages

`
qualys_parser -i report.csv --ip
`

Sample output:

```json
{
	"172.30.1.1": ["git-man"],
	"172.30.1.2": ["git-man"],
	"172.30.1.3": ["linux-image-aws", "linux-libc-dev"],
	"172.30.1.4": ["linux-image-aws", "linux-libc-dev"],
	"172.30.1.5": ["linux-image-aws", "linux-libc-dev"],
	"172.30.1.6": ["OpenSSH_7.2p2"]
}
```

With more details

`
qualys_parser -i report.csv --ip -d
`

Sample output:

```json
{
	"172.30.1.1": ["git-man | 1:2.7.4-0ubuntu1.6 | 1:2.7.4-0ubuntu1.7#"],
	"172.30.1.2": ["git-man | 1:2.7.4-0ubuntu1.6 | 1:2.7.4-0ubuntu1.7#"],
	"172.30.1.3": [
		"linux-image-aws | 4.4.0.1048.50 | 4.4.0.1099.103",
		"linux-libc-dev | 4.4.0-109.132 | 4.4.0-170.199#"
	],
	"172.30.1.4": [
		"linux-image-aws | 4.4.0.1048.50 | 4.4.0.1099.103",
		"linux-libc-dev | 4.4.0-109.132 | 4.4.0-170.199#"
	],
	"172.30.1.5": [
		"linux-image-aws | 4.4.0.1048.50 | 4.4.0.1099.103",
		"linux-libc-dev | 4.4.0-109.132 | 4.4.0-170.199#"
	],
	"172.30.1.6": ["OpenSSH_7.2p2 | Ubuntu-4ubuntu2.10, | OpenSSL"]
}
```

4. Quickly grab the vulnerable packages for a certain ip

`
qualys_parser -i report.csv --host 172.30.1.2 --ip
`

Sample output:

```bash
The vulnerable package(s) found for the host 172.30.1.2 are:
git-man
```

5. Quickly grab the ips a vulnerable package can be found in

`
qualys_parser -i report.csv --pkg git-man
`

Sample output:

```bash
The ip(s) found for the package git-man are:
172.30.1.1
172.30.1.2
```

6. List just the packages or ips without further info

`
qualys_parser -i real.csv -l
`

Sample output:

```bash
The vulnerable packages found :
git-man
linux-image-aws
linux-libc-dev
OpenSSH_7.2p2
There are a total of 4 of package(s) found
```
