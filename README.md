# Shodan Scripts

This repo contains script(s) for using the Shodan API.  Current script just performs searches and exports results to console or API.  Was a quick project for myself as I experimented with Shodan.io.

Shall not be held responsible for what you do with these.

## Prerequisites

Requires Python 3, and the following extra modules
- Shodan (https://github.com/achillean/shodan-python)
- IP Address (https://github.com/phihag/ipaddress)

# Getting Started

## shodan-search

The 'shodan-search' script is pretty straight forward, it will usually return summary information for port, os, country, org, domain, or you can run a full search and export the results to CSV file.  

Using API Key:
You can pass in the API key using --key or have it generate config file to store the key for later use:

```console
./shodan-search.py --key 123456789 --query net:192.168.8.0/24 --summary yes # run with the key

./shodan-search.py --key 123456789 --generate-config # creates a shodan.cfg file containing the key and using it in future calls.
```

Run a search with and retrieve summary information:

```console
./shodan-search.py --query net:192.168.8.0/24 --summary yes
```

Run a full search and export to CSV, exports the ip, port, os, org, hostnames, domains, data by default:

```console
./shodan-search.py --query net:192.168.8.0/24 --summary no  # exports to shodan.csv
./shodan-search.py --query net:192.168.8.0/24 --summary no --csv myexport.csv  # exports to myexport.csv
./shodan-search.py --query net:192.168.8.0/24 --summary no --console  # also prints results to console
```

No need to quote the query:

```console
./shodan-search.py --query net:192.168.8.0/24 apache --summary no  
```

Search for a Host, get back the Org, Ports, and Banners etc:

```console
./shodan-search.py --ip 8.8.8.8
```

Validate the Shodan API Key:

```console
./shodan-search.py --info

Shodan Search

Shodan API Key Info
------------------------------
Plan: dev
Unlocked: True
Unlocked Left: 100
Scan Credits: 100
Query Credits: 100
```

Full Usage can be found in the help:

```console
./shodan-search.py --help

Shodan Search
usage: shodan-search.py [-h] [--key KEY] [--generate-config] [--ip IP]
                        [--query QUERY [QUERY ...]] [--summary {yes,no}]
                        [--csv CSVNAME] [--console] [--info] [--version]

Shodan Search Script

optional arguments:
  -h, --help            show this help message and exit
  --key KEY, -k KEY     shodan api key, you can supply as a paramater or via
                        configuration file (shodan.cfg)
  --generate-config     stores the api key the config file
  --ip IP, -i IP        ip address to search for
  --query QUERY [QUERY ...], -q QUERY [QUERY ...]
                        shodan query to run
  --summary {yes,no}    run search in summary mode, saving search credits,
                        defaults to yes.
  --csv CSVNAME         csv file to export results to, defaults to shodan.csv
  --console             print search results to the console
  --info                validate the shodan api key
  --version, -v         show program's version number and exit
  ```

# Author
[M. Beauchamp](https://github.com/beauchompers)


# Acknowledgements
- AChillean - https://github.com/achillean/shodan-python