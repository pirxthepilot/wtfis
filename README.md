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

### Virustotal

The primary source of information. Retrieves:

* [Hostname (FQDN), domain or IP](https://developers.virustotal.com/reference/domains-1)
    * Latest analysis stats with vendor detail
    * Reputation score (based on VT community votes)
    * Popularity ranks (Alexa, Cisco Umbrella, etc.) (FQDN and domain only)
    * Categories (assigned by different vendors)
    * Last IP or DNS record update date
    * Date DNS record was last retrieved by VT (FQDN and domain only)
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

### IP2WHOIS

Optionally used if creds are provided and Passivetotal creds are not supplied. (i.e. second in line for Whois information)

* [Whois](https://www.ip2location.io/ip2whois-documentation)
    * Various whois data about the domain itself

As above, IP2WHOIS is recommended over Virustotal, if a Passivetotal account cannot be obtained.

### IPWhois

IP address enrichments for VT resolutions. For each IP, retrieves the ASN, Org, ISP and Geolocation. (Not to be confused with IP2WHOIS, which provides domain Whois data.)

### Shodan

Alternative IP address enrichment source. GETs data from the `/shodan/host/{ip}` endpoint (see [doc](https://developer.shodan.io/api)). For each IP, retrieves:

* ASN, Org, ISP and Geolocation
* Operating system (if available)
* List of open ports and detected services
* Tags (assigned by Shodan)


## Install

```
$ pip install wtfis
```

## Setup

wtfis uses these environment variables:

* `VT_API_KEY` (required) - Virustotal API key
* `PT_API_KEY` (optional) - Passivetotal API key
* `PT_API_USER` (optional) - Passivetotal API user
* `SHODAN_API_KEY` (optional) - Shodan API key
* `IP2WHOIS_API_KEY` (optional) - IP2WHOIS API key
* `WTFIS_DEFAULTS` (optional) - Default arguments

Set these using your own method.

Alternatively, create a file in your home directory `~/.env.wtfis` with the above declarations. See [.env.wtfis.example](./.env.wtfis.example) for a template. **NOTE: Don't forget to `chmod 400` the file!**


## Usage

```
usage: wtfis [-h] [-m N] [-s] [-n] [-1] [-V] entity

positional arguments:
  entity                Hostname, domain or IP

optional arguments:
  -h, --help            show this help message and exit
  -m N, --max-resolutions N
                        Maximum number of resolutions to show (default: 3)
  -s, --use-shodan      Use Shodan to enrich IPs
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

### Display options

For FQDN and domain lookups, you can increase or decrease the maximum number of displayed IP resolutions with `-m NUMBER` or `--max-resolutions=NUMBER`. The upper limit is 10. If you don't need resolutions at all, set the number to `0`.

To show all panels in one column, use the `-1` or `--one-column` flag.

![](https://github.com/pirxthepilot/wtfis/blob/main/imgs/example-one-column.png?raw=true)

Panels can be displayed with no color with `-n` or `--no-color`. 

![](https://github.com/pirxthepilot/wtfis/blob/main/imgs/example-no-color.png?raw=true)

### Defaults

Default arguments can be defined by setting the `WTFIS_DEFAULTS` environment variable. For example, to use shodan and display results in one column by default:

```
WTFIS_DEFAULTS="-s -1"
```

If an argument is in `WTFIS_DEFAULTS`, then specifying the same argument during command invocation **negates** that argument. So in the example above, if you then run:

```
wtfis example.com -s
```

then Shodan will NOT be used.

Note that maximum resolutions (`-m N, --max-resolutions N`) cannot be defined in defaults at the moment.


## TODOs

* Consider adding Greynoise enrichment (RIOT, etc.)
* URL lookup
* Keyring support
