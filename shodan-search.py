#! /usr/bin/env python3
# searches shodan among other things 

import configparser, sys, os.path, argparse, csv, io
from time import sleep

# make sure we have shodan module installed
try:
    import shodan
except:
    print("Shodan module not found, install from here (https://github.com/achillean/shodan-python)")
    sys.exit(1)

# make sure we have the ipaddress module installed
try:
    import ipaddress
except:
    print("Ipaddress module not found, install from here (https://github.com/phihag/ipaddress)")
    sys.exit(1)

# utility functions
# join the query so we don't need quotes
class JoinQuery(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, " ".join(values))

def get_key():
    # grab the api key from the config file
    if os.path.isfile("shodan.cfg"):
        try:
            config = configparser.ConfigParser()
            config.read("shodan.cfg")
            key = config['shodan']['key']
        except:
            print("Error: No Shodan api key found, please use config file or pass in key with -k...")
            sys.exit(1)

    return key

# validate ip
def validate_ip(ip):
    #validate if the ip is actually an ip before we search
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Error: {} is not a valid ip address...".format(ip))
        sys.exit(1)

def generate_config(key):
    
    # validate the key
    try:
        search_info(key)
    except Exception as e:
        print("Error: API key is invalid")
        sys.exit(1)

    # write file    
    try:
        f = open("shodan.cfg","w+")
        f.write("[shodan]\nkey = {}".format(key))
        f.close
        print("Generated new config file (shodan.cfg)\n")
    except Exception as e:
        print("Error: Unable to generate config file")
        print("Error: {}".format(e))
    
    return True

def print_console(data):
    print("\nHost Info")
    print("-" * 30)
    
    # Loop through the matches and print each IP
    for service in data['matches']:
        print("IP: {}, Port: {}, Org: {}".format(service.get('ip_str', 'n/a'), service.get('port', 'n/a'), service.get('org', 'n/as')))

    return True
    
def generate_csv(data,csvname):
    # make sure file extension is .csv
    if csvname.endswith('.csv'):
        filename = csvname
    else:
        filename = csvname + ".csv"

    # build a subset of the data
    headers= ['ip_str', 'port', 'os', 'org', 'hostnames', 'domains', 'data']
    csv_list = []
    for service in data['matches']:
        csv_row = {}
        for x in headers:
            if x in service.keys():
                csv_row[x] = service[x]
        csv_list.append(csv_row)

    with open(filename, 'w') as csvfile:
        fieldnames = ['ip_str', 'port', 'os', 'org', 'hostnames', 'domains', 'data']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for service in csv_list:
            writer.writerow(service)

    print("\nResults written to {}...\n".format(filename))
    return True

# search functions
def search_info(key):
    # returns information about the shodan api key being used.
    
    try:
        api = shodan.Shodan(key)
        info = api.info()
        print("\nShodan API Key Info")
        print("-" * 30)
        print("Plan: {}\nUnlocked: {}\nUnlocked Left: {}\nScan Credits: {}\nQuery Credits: {}\n".format(info['plan'], info['unlocked'], info['unlocked_left'], info['scan_credits'], info['query_credits']))
        sleep(2)
    except Exception as e:
        print("Error during Info request: {}".format(e))
        sys.exit(1)

    return info

def search_ip(ip, key):  
    # search and return information about a specific host 
    try:
        api = shodan.Shodan(key)
        print("Searching for {}".format(ip))
        host = api.host(ip)

        print("\nHost Info")
        print("-" * 30)
        print("\nIP: {}\nOrganization: {}\nOperating System: {}\nCountry Code: {}".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'), host.get('country_code', 'n/a')))

        print("\nBanner Info")
        print("-" * 30)
        for item in host['data']:
            print("\nPort: {}\nTransport: {}\nBanner: {}".format(item['port'], item['transport'], item['data']))

        sleep(2) # sleep for 2 seconds, self rate limit
        sys.exit(0)
    except Exception as e:
        print("Error during Host search: {}".format(e))
        sys.exit(1)

def search_query(query, key, csvname, console=False):
    # run query on shodan, return results
    # option to write to csv or print quickly to console
    
    # return a summary 
    FACETS = [
        'org',
        'domain',
        'os',
        'port',
        'country',
    ]

    FACET_TITLES = {
        'org': 'Top 5 Organizations',
        'domain': 'Top 5 Domains',
        'os': 'Top 5 Operating Systems',
        'port': 'Top 5 Ports',
        'country': 'Top 5 Countries'
    }

    try:
        api = shodan.Shodan(key)
        result = api.search(query, facets=FACETS)
    except Exception as e:
        print("Error during Search: {}".format(e))
        sys.exit(1)

    print("\nShodan Search Info")
    print("-" * 30)
    print("Query: {}".format(query))
    print("Total Results: {}\n".format(result['total']))

    # Print the summary info from the facets
    for facet in result['facets']:
        print(FACET_TITLES[facet])

        for term in result['facets'][facet]:
            print("{}: {}".format(term['value'], term['count']))

        print(" ")

    # export to csv
    generate_csv(result,csvname)

    # print to console if console is True
    if console == True:
        print_console(result)

    
    
    sleep(2) # sleep for 2 seconds, self rate limit
    sys.exit(0)

def search_summary(query, key):
    # run a query search on shodan, return a summary of results

    # The list of properties we want summary information on, modify as appropriate
    FACETS = [
        'org',
        'domain',
        'os',
        'port',
        'asn',
        'country'
    ]

    FACET_TITLES = {
        'org': 'Top 5 Organizations',
        'domain': 'Top 5 Domains',
        'os': 'Top 5 Operating Systems',
        'port': 'Top 5 Ports',
        'asn': 'Top 5 Autonomous Systems',
        'country': 'Top 5 Countries'
    }

    try:
        api = shodan.Shodan(key)
        summary = api.count(query, facets=FACETS)

        print("\nShodan Summary Info")
        print("-" * 30)
        print("Query: {}".format(query))
        print("Total Results: {}\n".format(summary['total']))

        # Print the summary info from the facets
        for facet in summary['facets']:
            print(FACET_TITLES[facet])

            for term in summary['facets'][facet]:
                print("{}: {}".format(term['value'], term['count']))

            # Print an empty line between summary info
            print(" ")
    except Exception as e:
        print("Error: {}".format(e))
        sys.exit(1)

    sleep(2) # sleep for 2 seconds, self rate limit
    sys.exit(0)

def __main__():
    # shodan search script

    # grab args, grab config file if exists, and search!
    print("Shodan Search")
    parser = argparse.ArgumentParser(description='Shodan Search Script')
    parser.add_argument('--key', '-k', dest='key', help='shodan api key, you can supply as a paramater or via configuration file (shodan.cfg)')
    parser.add_argument('--generate-config', dest='generate', action='store_true', help='stores the api key the config file')
    parser.add_argument('--ip', '-i', dest='ip', help='ip address to search for')
    parser.add_argument('--query', '-q', dest='query', action=JoinQuery, nargs='+', help='shodan query to run')
    parser.add_argument('--summary', dest='summary', choices=['yes', 'no'], default='yes', help='run search in summary mode, saving search credits, defaults to yes.')
    parser.add_argument('--csv', dest='csvname', default='shodan.csv', help='csv file to export results to, defaults to shodan.csv')
    parser.add_argument('--console', dest='console', action='store_true', default=False, help="print search results to the console")
    parser.add_argument('--info', dest='info', action='store_true', help='validate the shodan api key')
    parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()

    # check we have an api key, error if no key is available
    if args.key == None:
        args.key = get_key()

    # generate config file with api key
    if args.generate:
        generate_config(args.key)
        sys.exit(0)

    # display info on our api key
    if args.info:
        search_info(args.key)
        sys.exit(0)

    # make sure it's either a host search or query search
    if args.ip != None and args.query != None:
        print("Error: Can search either host or query, not both...")
        sys.exit(parser.print_help())
    elif args.ip == None and args.query == None:
        print("Error: Need to supply an ip (-i) or query (-q) for this to work...")
        sys.exit(parser.print_help())

    # search for stuff!

    # search by ip
    if args.ip != None:
        # validate this is an ip
        validate_ip(args.ip)
        # run search    
        search_ip(args.ip,args.key)

    # run the search, either via summary or deep search if summary = no
    if  args.query != None and args.summary == "yes":
        search_summary(args.query,args.key)
    elif args.query != None and args.summary == "no":
        if args.console:
            search_query(args.query,args.key,args.csvname,console=True)
        else:
            search_query(args.query,args.key,args.csvname)

if __name__ == '__main__':
    __main__()