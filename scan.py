import urllib3
import subprocess
import maxminddb
import json
import time
import sys
import re

# Helps generate JSON dictionary for the output
def generate_output(scanner_list):
    scans = {}

    for scanner, output in scanner_list.items():
        if output == "null":
            scans[scanner] = None
        elif output is None:
            #scans[scanner] = output
            pass
        else:
            scans[scanner] = output

    return scans


# CREDIT: Code for finding matches taken from this website https://blog.finxter.com/how-to-find-all-matches-using-regex/
# Finds all matches in a string provided a given pattern
def find_matches(pattern, string):
    matches = []

    while True:
        match = pattern.search(string)

        if match:
            matches.append(match.group(0))
            string = string[match.end():]
        else:
            return matches


# Compiles the given pattern
def compile_patt(pattern):
    return re.compile(pattern, re.IGNORECASE)


# Runs the IPv4 or IPv6 Scanner
def scan_ips(domain, scanner_list, ip_type):
    ip_output = None

    try:
        if ip_type == "A":
            # CREDIT: regex for IPv4 was generated from this website: https://regex-generator.olafneumann.org/
            pattern = compile_patt(
                r"\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b")
            string = (subprocess.check_output(["nslookup", domain],
                                              timeout=2,
                                              stderr=subprocess.STDOUT).decode("utf-8"))
        else:
            # CREDIT: regex for IPv6 was sourced from this website: https://regexr.com/3bu43
            pattern = compile_patt(
                r"(([a-fA-F0-9]{1,4}|):){1,7}([a-fA-F0-9]{1,4}|:)")
            string = (subprocess.check_output(["nslookup", "-type=AAAA", domain],
                                              timeout=2,
                                              stderr=subprocess.STDOUT).decode("utf-8"))

        ip_output = find_matches(pattern, string.split("\n\n")[1])

    except:
        sys.stderr.write(
            "Attempt to connect to " + domain + " failed or timed out. Skipping the scan for type " + ip_type + " addresses.\n\n")

    if ip_type == "A":
        scanner_list["ipv4_addresses"] = ip_output
    else:
        scanner_list["ipv6_addresses"] = ip_output


# Gets the server header from an HTTP get request
def get_server(domain, scanner_list):
    global http
    http = urllib3.PoolManager()

    try:
        request = http.request('GET', domain, retries=False, timeout=urllib3.Timeout(2))
    except:
        sys.stderr.write(
            "Attempt to connect to " + domain + " failed or timed out. Skipping the scan for http_server.\n\n")
        scanner_list["http_server"] = None
        return

    if "server" in request.headers:
        server = request.headers['Server']
    else:
        server = "null"

    scanner_list["http_server"] = server


def check_encryption(domain, scanner_list):
    global http
    http = urllib3.PoolManager()
    location = ""
    redirects = 0

    try:
        request = http.request('GET', domain, retries=False, timeout=urllib3.Timeout(2))
    except:
        sys.stderr.write(
            "Attempt to connect to " + domain + " failed or timed out. Skipping the scan for insecure_http and redirect_to_https.\n\n")
        scanner_list["insecure_http"] = None
        scanner_list["redirect_to_https"] = None
        return

    status = request.status

    if "location" in request.headers:
        location = request.headers['location']
    else:
        scanner_list["insecure_http"] = True
        scanner_list["redirect_to_https"] = False
        return

    while True:
        if redirects >= 10:
            scanner_list["insecure_http"] = True
            scanner_list["redirect_to_https"] = False
            return
        elif location:
            if "https" in location:
                scanner_list["insecure_http"] = True
                scanner_list["redirect_to_https"] = True
                return
            else:
                domain = location

                try:
                    request = http.request('GET', domain, retries=False, timeout=urllib3.Timeout(2))
                except:
                    sys.stderr.write(
                        "Attempt to connect to " + domain + " failed or timed out. Skipping the scan for insecure_http and redirect_to_https.\n\n")
                    scanner_list["insecure_http"] = None
                    scanner_list["redirect_to_https"] = None
                    return

                if "location" in request.headers:
                    location = request.headers['location']
                else:
                    scanner_list["insecure_http"] = True
                    scanner_list["redirect_to_https"] = False
                    return

                redirects += 1
        elif status >= 400:
            scanner_list["insecure_http"] = False
            scanner_list["redirect_to_https"] = False
            return
        elif status == 200:
            scanner_list["insecure_http"] = True
            scanner_list["redirect_to_https"] = False
            return


def scan_hsts(domain, scanner_list):
    global http
    http = urllib3.PoolManager()
    location = ""
    redirects = 0

    try:
        request = http.request('GET', domain, retries=False, timeout=urllib3.Timeout(2))
    except:
        sys.stderr.write(
            "Attempt to connect to " + domain + " failed or timed out. Skipping the scan for hsts.\n\n")
        scanner_list["hsts"] = None
        return

    status = request.status

    if "location" in request.headers:
        location = request.headers['location']
    else:
        if "strict-transport-security" in request.headers:
            scanner_list["hsts"] = True
        else:
            scanner_list["hsts"] = False
        return

    while True:
        if redirects >= 10:
            if "strict-transport-security" in request.headers:
                scanner_list["hsts"] = True
            else:
                scanner_list["hsts"] = False
            return
        elif location:
            domain = location

            try:
                request = http.request('GET', domain, retries=False, timeout=urllib3.Timeout(2))
            except:
                sys.stderr.write(
                    "Attempt to connect to " + domain + " failed or timed out. Skipping the scan for hsts.\n\n")
                scanner_list["hsts"] = None
                return

            if "location" in request.headers:
                location = request.headers['location']
            else:
                if "strict-transport-security" in request.headers:
                    scanner_list["hsts"] = True
                else:
                    scanner_list["hsts"] = False
                return

            redirects += 1
        else:
            if "strict-transport-security" in request.headers:
                scanner_list["hsts"] = True
            else:
                scanner_list["hsts"] = False
            return

# Scans TLS and root_ca.
def scan_TLS(domain, scanner_list):
    global response_1
    global response_2

    tls_versions = []

    ciphers = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    cmd = "sh -c \"echo | openssl s_client -tls1_3 -connect " + domain + ":443\""

    try:
        response_1 = (subprocess.check_output(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", domain],
                                              timeout=2,
                                              stderr=subprocess.STDOUT).decode("utf-8"))
        # CREDIT: Code below was partially taken from TA Sen Lin's post here: https://piazza.com/class/lcgnifepxs24rm/post/342
        check_tls3 = subprocess.Popen(cmd,
                                      shell=True,
                                      stderr=subprocess.PIPE,
                                      stdout=subprocess.PIPE)
        response_2 = check_tls3.communicate(timeout=2)[0].decode("utf-8")

        for cipher in ciphers:
            if cipher in response_1:
                tls_versions.append(cipher)
            if cipher in response_2:
                tls_versions.append(cipher)
    except:
        sys.stderr.write(
            "Attempt to connect to " + domain + " failed or timed out. Skipping the scan for TLS.\n\n")

    scanner_list["tls_versions"] = tls_versions


def root_ca(domain,scanner_list):
    root_cert = "null"
    if "TLS" not in "".join(scanner_list["tls_versions"]):
        scanner_list["root_ca"] = "null"
        return

    cmd = "echo | openssl s_client -connect {}:443".format(domain)
    try:
        process = subprocess.Popen(cmd,
                                      shell=True,
                                      stderr=subprocess.PIPE,
                                      stdout=subprocess.PIPE)
        response = process.communicate(timeout=2)[0].decode("utf-8")

    # Could not connect.
    except:
        sys.stderr.write("Attempt to find root_ca failed. Skipping scan for root_ca.\n\n")
        scanner_list["root_ca"] = root_cert
        return

    try:
        # Find root ca issuer
        issuer = find_matches(compile_patt(r'i:(.|\n)*?---'), response)[0]
        # Find root cert
        # I LOVE ROOT CERTS!!!!!!!!!!!!!!!!!!!!!!!!
        root_cert = find_matches(compile_patt(r'\sO\s= .*?,\s[A-Z][A-Z]'), issuer)[-1]

        # Some CA issuers have "Asdf, Inc". The comma needs to be ignored.
        if "\"" in root_cert:
            root_cert = find_matches(compile_patt(r'\sO\s=.*?",\s[A-Z][A-Z]'), issuer)[-1]
            end = len(root_cert)
            root_cert = root_cert[6:end-5]

        # Proceed normally
        else:
            # Trim out " O = ... ,"
            end = len(root_cert)
            # Splicing is weird and the end-1 index is excluded.
            root_cert = root_cert[5:end-4]

    # Could not find root_cert.
    except:
        sys.stderr.write("Attempt to find root_ca failed. Skipping scan for root_ca.\n\n")

    scanner_list["root_ca"] = root_cert


# Returns RDNS for a given IPv4
# NOTE: Depends on scanner_list["ipv4_addresses"]
def rdns_names(domain, scanner_list):
    ip_list = scanner_list["ipv4_addresses"]
    rdns_list = []
    if not ip_list:
        sys.stderr.write("Attempt to find rdns for {} failed. Skipping...\n\n".format(domain))
        scanner_list["rdns_names"] = rdns_list
        return

    for ip in ip_list:
        try:
            reverse_string = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            cmd = "nslookup -type=PTR {}".format(reverse_string)
            # CREDIT: Code below was partially taken from TA Sen Lin's post here: https://piazza.com/class/lcgnifepxs24rm/post/342
            process = subprocess.Popen(cmd,
                                          shell=True,
                                          stderr=subprocess.PIPE,
                                          stdout=subprocess.PIPE)
            msg = process.communicate(timeout=2)[0].decode("utf-8")

        except:
            sys.stderr.write("Attempt to find rdns for {} failed. Skipping...\n\n".format(ip))
            continue

        try:
            patt = compile_patt(r"name\s=\s.(.|\n)*Authoritative\sanswers")
            matches = find_matches(patt, msg)[0].split("\n")
            end = len(matches)
            # The method of splitting leaves ['', 'Authoritative...'] in the list, so this splices them off.
            matches = matches[0:end-2]
            for match in matches:
                patt = compile_patt(r"name\s=\s.*\.")
                addr = find_matches(patt, match)[0]

                # Trim up the address
                addr = addr[7:-1]
                rdns_list.append(addr)

        except:
            sys.stderr.write("Error getting reverse DNS for {}. Skipped.\n\n".format(ip))

    scanner_list["rdns_names"] = rdns_list


# Returns a RTT range [min, max] of the IPv4 address in ms
# NOTE: Depends on scanner_list["ipv4_addresses"]
def rtt_range(domain, scanner_list):
    ip_list = scanner_list["ipv4_addresses"]
    min = float("inf")
    max = 0
    ports = [80, 22, 443]

    # No IPv4 address: return null
    if not ip_list:
        scanner_list["rtt_range"] = "null"
        sys.stderr.write("Attempt to find RTT for {} failed. Skipping...\n\n".format(domain))
        return

    for ip in ip_list:
        for p in ports:
            try:
                # CREDIT: Code below was partially taken from TA Sen Lin's post here: https://piazza.com/class/lcgnifepxs24rm/post/342
                cmd = "sh -c \'time echo -e \"\x1dclose\x0d\" | telnet {} {}\'".format(ip, p)
                process = subprocess.Popen(cmd,
                                           shell=True,
                                           stderr=subprocess.PIPE,
                                           stdout=subprocess.PIPE)
                msg = process.communicate(timeout=2)[0].decode("utf-8")

                # CREDIT: regex for IPv6 was sourced from this website: https://regexr.com/3bu43
                # Finding "0m000s user" pattern, but RTT should not be over a minute... so we're omitting that part.
                pattern = compile_patt(r"\d\.\d\d\ds\suser")
                match = find_matches(pattern, msg)[0]
                time = float(match[0:5])
                if time < min:
                    min = time
                if time > max:
                    max = time

            # Didn't connect, keep trying other ports
            except:
                sys.stderr.write("Attempt to connect to port {} failed.\n".format(p))
                # If we've tried all 3 ports to no avail, end it
                if p == 443:
                    scanner_list["rtt_range"] = "null"
                    return
                continue

            # Only need one port, break out of the port loop.
            break
    min *= 1000
    max *= 1000
    scanner_list["rtt_range"] = int(min), int(max)


# Returns geographical location of the IPv4 address based on maxminddb (City, Province, Country)
# NOTE: Depends on scanner_list["ipv4_addresses"]
def geo_locations(reader, scanner_list):
    ip = scanner_list["ipv4_addresses"]
    addresses = []
    for entry in ip:
        address = ""
        # Find city, province, and country of IP
        try:
            # I think this method is faster than creating a list then checking if None and removing None's
            city = reader.get(entry)["city"]["names"]["en"]
            address = address + city + ", "
        except:
            pass
        try:
            subdivision = reader.get(entry)["subdivisions"]["names"]["en"]
            address = address + subdivision + ", "
        except:
            pass
        try:
            country = reader.get(entry)["country"]["names"]["en"]
            address = address + country
        except:
            pass

        # No duplicate addresses
        if address in addresses:
            continue

        addresses.append(address)

    scanner_list["geo_locations"] = addresses


# Main body of the program
def main(input_file, output_file):
    urllib3.disable_warnings()

    domain_list = open(input_file, "r")
    domain_dict = {}

    mmdb_reader = maxminddb.open_database("GeoLite2-City.mmdb")

    for domain in domain_list:
        domain = domain.strip('\n')
        scanner_list = {"scan_time": time.time()}
        scan_ips(domain, scanner_list, "A")
        scan_ips(domain, scanner_list, "AAAA")
        get_server(domain, scanner_list)
        check_encryption(domain, scanner_list)
        scan_hsts(domain, scanner_list)
        scan_TLS(domain, scanner_list)
        root_ca(domain, scanner_list)
        rdns_names(domain, scanner_list)
        rtt_range(domain, scanner_list)
        geo_locations(mmdb_reader, scanner_list)
        domain_dict[domain] = generate_output(scanner_list)

    domain_list.close()

    program_output = open(output_file, "w")
    program_output.write(json.dumps(domain_dict, indent=4))
    program_output.close()
    mmdb_reader.close()


in_file = sys.argv[1]
out_file = sys.argv[2]

main(in_file, out_file)
