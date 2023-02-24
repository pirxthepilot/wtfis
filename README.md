# wtfis

[![Tests](https://github.com/pirxthepilot/wtfis/actions/workflows/tests.yml/badge.svg)](https://github.com/pirxthepilot/wtfis/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/wtfis?color=blue&logo=pypi&logoColor=gold)](https://pypi.org/project/wtfis/)

Passive hostname, domain and IP lookup tool for non-robots

![](https://github.com/pirxthepilot/wtfis/blob/main/imgs/demo.gif?raw=true)


## WTF is it?

**wtfis** is a commandline tool that gathers information about a domain, FQDN or IP address using various OSINT services. Unlike other tools of its kind, it's built specifically for human consumption, providing results that are pretty (YMMV) and easy to read and understand.

This tool assumes that you are using free tier / community level accounts, and so makes as few API calls as possible to minimize hitting quotas and rate limits.

The project name is a play on "whois".


## Data Sources

| Service | Used in lookup | Required | Free Tier |
| --- | --- | --- | --- |
| [Virustotal](https://virustotal.com) | All | Yes | [Yes](https://www.virustotal.com/gui/join-us) |
| [Passivetotal](https://community.riskiq.com) | All | No | [Yes](https://community.riskiq.com/registration/)
| [IP2Whois](https://www.ip2whois.com) | Domain/FQDN | No | [Yes](https://www.ip2location.io/pricing#ip2whois)
| [IPWhois](https://ipwhois.io) | IP address | No | Yes (no signup) |
| [Shodan](https://shodan.io) | IP address | No | [No](https://account.shodan.io/billing) |
| [Greynoise](https://greynoise.io) | IP address | No | [Yes](https://www.greynoise.io/plans/community)

### Virustotal

The primary source of information. Retrieves:

* [Hostname (FQDN), domain or IP](https://developers.virustotal.com/reference/domains-1)
    * Latest analysis stats with vendor detail
    * Reputation score (based on VT community votes)
    * Popularity ranks (Alexa, Cisco Umbrella, etc.) (FQDN and domain only)
    * Categories (assigned by different vendors)
* [Resolutions](https://developers.virustotal.com/reference/domain-resolutions) (FQDN and domain only)
    * Last n IP addresses (default: 3, max: 10)
    * Latest analysis stats of each IP above
* [Whois](https://developers.virustotal.com/reference/whois)
    * Fallback only: if Passivetotal creds are not available
    * Various whois data about the domain itself

### Passivetotal (RiskIQ)

Optionally used if creds are provided. Retrieves:

* [Whois](https://api.riskiq.net/api/whois_pt/)
    * Various whois data about the domain itself

Passivetotal is recommended over Virustotal for whois data for a couple of reasons:

* VT whois data format is less consistent
* PT whois data tends to be of better quality than VT. Also, VT's registrant data is apparently [anonymized](https://developers.virustotal.com/reference/whois).
* You can save one VT API call by offloading to PT

### IP2Whois

Optionally used if creds are provided and Passivetotal creds are not supplied. (i.e. second in line for Whois information)

* [Whois](https://www.ip2location.io/ip2whois-documentation)
    * Various whois data about the domain itself

As above, IP2Whois is recommended over Virustotal, if a Passivetotal account cannot be obtained.

### IPWhois

Default enrichment for IP addresses. Retrieves:

* ASN, Org, ISP and Geolocation

IPWhois should not be confused with IP2Whois, which provides domain Whois data.

### Shodan

Alternative IP address enrichment source. GETs data from the `/shodan/host/{ip}` endpoint (see [doc](https://developer.shodan.io/api)). For each IP, retrieves:

* ASN, Org, ISP and Geolocation
* List of open ports and services
* Operating system (if available)
* Tags (assigned by Shodan)

### Greynoise

Supplementary IP address enrichment source. Using its [community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api), wtfis will show whether an IP is in one of Greynoise's datasets:

* **Noise**: IP has been seen regularly scanning the Internet
* **RIOT**: IP belongs to a common business application (e.g. Microsoft O365, Google Workspace, Slack)

More information about the datasets [here](https://docs.greynoise.io/docs/understanding-greynoise-data-sets).

In addition, the API also returns Greynoise's [classification](https://docs.greynoise.io/docs/understanding-greynoise-classifications) of an IP (if available). Possible values are **benign**, **malicious**, and **unknown**.


## Install

```
$ pip install wtfis
```

To install via `conda` (from conda-forge), see [wtfis-feedstock](https://github.com/conda-forge/wtfis-feedstock).


## Setup

wtfis uses these environment variables:

* `VT_API_KEY` (required) - Virustotal API key
* `PT_API_KEY` (optional) - Passivetotal API key
* `PT_API_USER` (optional) - Passivetotal API user
* `IP2WHOIS_API_KEY` (optional) - IP2WHOIS API key
* `SHODAN_API_KEY` (optional) - Shodan API key
* `GREYNOISE_API_KEY` (optional) - Greynoise API key
* `WTFIS_DEFAULTS` (optional) - Default arguments

Set these using your own method.

Alternatively, create a file in your home directory `~/.env.wtfis` with the above declarations. See [.env.wtfis.example](./.env.wtfis.example) for a template. **NOTE: Don't forget to `chmod 400` the file!**


## Usage

```
usage: wtfis [-h] [-m N] [-s] [-g] [-n] [-1] [-V] entity

positional arguments:
  entity                Hostname, domain or IP

optional arguments:
  -h, --help            show this help message and exit
  -m N, --max-resolutions N
                        Maximum number of resolutions to show (default: 3)
  -s, --use-shodan      Use Shodan to enrich IPs
  -g, --use-greynoise   Enable Greynoise for IPs
  -n, --no-color        Show output without colors
  -1, --one-column      Display results in one column
  -V, --version         Print version number
```

Basically:

```
$ wtfis FQDN_OR_DOMAIN_OR_IP
```

and you will get results organized by panel, similar to the image above.

Defanged input is accepted (e.g. `api[.]google[.]com`).

If your terminal supports it, FQDN, domain, and IP headings are clickable hyperlinks that point to the appropriate pages on the VT or PT (RiskIQ) website.

### Shodan enrichment

Shodan can be used to enrich the IP addresses (instead of IPWhois). Invoke with the `-s` or `--use-shodan` flag.

![](https://github.com/pirxthepilot/wtfis/blob/main/imgs/example-shodan.png?raw=true)

The `Services` field name is a hyperlink (if supported by the terminal) that takes you to the IP in the Shodan web interface.

### Greynoise enrichment

To enable Greynoise, invoke with the `-g` or `--use-greynoise` flag. Because the API quota is quite low (50 requests per week as of March 2023), this lookup is off by default.

![](https://github.com/pirxthepilot/wtfis/blob/main/imgs/example-greynoise.png?raw=true)

The `Greynoise` field name is also a hyperlink (if terminal-supported) that points to the IP entry in the Greynoise web interface, where more context is shown.


### Display options

For FQDN and domain lookups, you can increase or decrease the maximum number of displayed IP resolutions with `-m NUMBER` or `--max-resolutions=NUMBER`. The upper limit is 10. If you don't need resolutions at all, set the number to `0`.

To show all panels in one column, use the `-1` or `--one-column` flag.

![](https://github.com/pirxthepilot/wtfis/blob/main/imgs/example-one-column.png?raw=true)

Panels can be displayed with no color with `-n` or `--no-color`. 

![](https://github.com/pirxthepilot/wtfis/blob/main/imgs/example-no-color.png?raw=true)

### Defaults

Default arguments can be defined by setting the `WTFIS_DEFAULTS` environment variable. For example, to use shodan and display results in one column by default:

```
WTFIS_DEFAULTS=-s -1
```

If an argument is in `WTFIS_DEFAULTS`, then specifying the same argument during command invocation **negates** that argument. So in the example above, if you then run:

```
$ wtfis example.com -s
```

then Shodan will NOT be used.

Note that maximum resolutions (`-m N, --max-resolutions N`) cannot be defined in defaults at the moment.


## Docker

wtfis can be run from a Docker image. First, build the image (using the included [Dockerfile](./Dockerfile)) by running:

```
$ make docker-image
```

The image will have the latest _tagged_ version (not necessarily from the latest commit) wtfis. This ensures that you are getting a stable release.

Two ways you can run the image:

Ensure `.env.wtfis` is in your home directory and set with the necessary envvars. Then simply run:

```
$ make docker-run
```

This is an alias to

```
$ docker run --env-file=${HOME}/.env.wtfis -it wtfis
```

Note that each definition must NOT have any spaces before and after the equal sign (`FOO=bar`, not `FOO = bar`).

Altenatively, you can set the environment variables yourself, then run, e.g.:

```
$ docker run -e VT_API_KEY -e SHODAN_API_KEY -it wtfis
```
