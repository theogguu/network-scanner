# Network Scanner

## Description

**This project was co-written with @oleande-r.**

This network scanner scans a domain and outputs a report of security features and network capabilities using the [texttable](https://pypi.org/project/texttable/) library. 

The scanner probes for the following:
- "scan_time": the time of the scan in Unix Epoch seconds because why not.
- "ipv4_addresses": a list of IPv4 addresses associated with the domain.
- "ipv6_addresses": a list of IPv6 addresses associated with the domain.
- "http_server": the web server software as reported in the http [server header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server) response
- "insecure_http": if the server listens for unencrypted HTTP requests on port 80
- "redirect_to_https": if unencrypted HTTP requests on port 80 are redirected to HTTPS requests on port 443
- "hsts": if the domain supports [HTTP Strict Transport Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security%20)
- "tls_versions": versions of [Transport Layer Security (TLS/SSL)](https://en.wikipedia.org/wiki/Transport_Layer_Security) supported
- "root_ca": the root certificate authority that validates the server's public key. note: returns null if TLS is not supported
- "rdns_names": the [reverse DNS names](https://en.wikipedia.org/wiki/Reverse_DNS_lookup) of the IPv4 addresses
- "rtt_range": shortest and longest round trip time of every IPv4 address
- "geo_locations": the approximate geographical location of the IPv4 addresses, as listed by the [MaxMind IP Geolocation database](https://maxminddb.readthedocs.io/en/latest/)

## Usage
You will need to install the [maxminddb](https://maxminddb.readthedocs.io/en/latest/) and [urllib3](https://urllib3.readthedocs.io/en/stable/) libraries to run the scanner.

`$ pip install maxminddb`

`$ pip install urllib3`

### scan.py
scan.py takes a text file as input and outputs a .json:

`python3 scan.py [in-file.txt] [out-file.json]`

The input file should be formatted like such:

```youtube.com
northwestern.edu
google.com.hk
github.com

...

exampledomain.com
```
and etc.


### report.py

report.py takes in a .json (from scan.py) and outputs a .txt file.

`python3 report.py [in-file.json] [out-file.txt]`

report.py generates 5 tables: 
- a master table with the details of every scan ran
- a table with the RTT range for each domain, sorted from least lower-bound RTT to most.
- a table with the number of occurences of each web server software, sorted from most popular to least.
- a table with the number of occurences of each observed root CA, sorted from most popular to least.
- a table with the percentage of domains that support:
  - each tls version (tls_versions)
  - unencrypted HTTP requests on port 80 (insecure_http)
  - redirection from port 80 to 443 for unencrypted requests (redirect_to_https)
  - HSTS
  - IPv6 addresses

## Example Report
```
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
|      domain      |   scan_time    |  ipv4_addresses  |  ipv6_addresses  |   http_server    | insecure_http | redirect_to_http | hsts  |   tls_versions   |     root_ca      |    rdns_names    | rtt_range  |  geo_locations  |
|                  |                |                  |                  |                  |               |        s         |       |                  |                  |                  |            |                 |
+==================+================+==================+==================+==================+===============+==================+=======+==================+==================+==================+============+=================+
| northwestern.edu | 1679269982.501 | ['129.105.136.48 | []               | BigIP            | True          | True             | False | ['TLSv1.0',      | Comodo CA        | ['evcommon-      | [3, 3]     | ['United        |
|                  |                | ']               |                  |                  |               |                  |       | 'TLSv1.1',       | Limited          | caesar-vip.north |            | States']        |
|                  |                |                  |                  |                  |               |                  |       | 'TLSv1.2']       |                  | western.edu', 'c |            |                 |
|                  |                |                  |                  |                  |               |                  |       |                  |                  | nair.northwester |            |                 |
|                  |                |                  |                  |                  |               |                  |       |                  |                  | n.edu']          |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| mccormick.northw | 1679269983.242 | ['165.124.149.20 | []               | Apache/2.4.41    | True          | True             | False | ['TLSv1.2']      | Comodo CA        | ['davinci20.tech | [2, 2]     | ['United        |
| estern.edu       |                | ']               |                  | (Ubuntu)         |               |                  |       |                  | Limited          | .northwestern.ed |            | States']        |
|                  |                |                  |                  |                  |               |                  |       |                  |                  | u']              |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| kellogg.northwes | 1679269983.982 | ['165.124.147.15 | []               | Microsoft-       | True          | True             | False | ['TLSv1.2']      | Comodo CA        | ['kelloggalumni. | [2, 2]     | ['United        |
| tern.edu         |                | 0']              |                  | IIS/10.0         |               |                  |       |                  | Limited          | kellogg.northwes |            | States']        |
|                  |                |                  |                  |                  |               |                  |       |                  |                  | tern.edu']       |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| users.cs.northwe | 1679269984.618 | ['165.124.180.20 | []               | Apache           | True          | True             | False | ['TLSv1.2']      | Comodo CA        | []               | [2, 2]     | ['United        |
| stern.edu        |                | ']               |                  |                  |               |                  |       |                  | Limited          |                  |            | States']        |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| it.eecs.northwes | 1679269985.081 | ['129.105.5.142' | []               | Apache/2.4.37    | True          | False            | False | ['TLSv1.2',      | Unspecified      | []               | [2, 2]     | ['Chicago,      |
| tern.edu         |                | ]                |                  | (Red Hat         |               |                  |       | 'TLSv1.3']       |                  |                  |            | United States'] |
|                  |                |                  |                  | Enterprise       |               |                  |       |                  |                  |                  |            |                 |
|                  |                |                  |                  | Linux)           |               |                  |       |                  |                  |                  |            |                 |
|                  |                |                  |                  | OpenSSL/1.1.1k   |               |                  |       |                  |                  |                  |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| uchicago.edu     | 1679269985.533 | ['34.200.129.209 | []               | Apache           | True          | True             | False | []               | None             | ['ec2-34-200-129 | [26, 26]   | ['United        |
|                  |                | ']               |                  |                  |               |                  |       |                  |                  | -209.compute-1.a |            | States']        |
|                  |                |                  |                  |                  |               |                  |       |                  |                  | mazonaws.com']   |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| illinois.edu     | 1679269988.061 | ['192.17.172.3'] | []               | Apache/2.2.15    | True          | True             | False | ['TLSv1.0',      | Comodo CA        | ['tardis.techser | [6, 6]     | ['Urbana,       |
|                  |                |                  |                  | (Red Hat)        |               |                  |       | 'TLSv1.1',       | Limited          | vices.illinois.e |            | United States'] |
|                  |                |                  |                  | mod_ssl/2.2.15 O |               |                  |       | 'TLSv1.2']       |                  | du']             |            |                 |
|                  |                |                  |                  | penSSL/1.0.1e-fi |               |                  |       |                  |                  |                  |            |                 |
|                  |                |                  |                  | ps               |               |                  |       |                  |                  |                  |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| stevetarzia.com  | 1679269989.371 | ['3.143.61.245'] | []               | Apache/2.4.55 () | True          | True             | False | ['TLSv1.0',      | Internet         | ['waffles.stevet | [12, 12]   | ['Columbus,     |
|                  |                |                  |                  | OpenSSL/1.0.2k-f |               |                  |       | 'TLSv1.1',       | Security         | arzia.com']      |            | United States'] |
|                  |                |                  |                  | ips PHP/5.4.16   |               |                  |       | 'TLSv1.2']       | Research Group   |                  |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| clocktab.com     | 1679269991.084 | ['172.67.139.104 | ['2606:4700:3037 | cloudflare       | True          | True             | False | ['TLSv1.0',      | Baltimore        | []               | [3, 4]     | ['United        |
|                  |                | ',               | ::6815:3693', '2 |                  |               |                  |       | 'TLSv1.1',       |                  |                  |            | States']        |
|                  |                | '104.21.54.147'] | 606:4700:3030::a |                  |               |                  |       | 'TLSv1.2',       |                  |                  |            |                 |
|                  |                |                  | c43:8b68']       |                  |               |                  |       | 'TLSv1.3']       |                  |                  |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| auditoryneurosci | 1679269991.931 | ['144.214.26.111 | []               | Apache/2.4.52    | True          | True             | False | []               | None             | ['twinkle.bms.ci | [300, 300] | ['Central, Hong |
| ence.com         |                | ']               |                  | (Ubuntu)         |               |                  |       |                  |                  | tyu.edu.hk']     |            | Kong']          |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| asee.org         | 1679269998.097 | ['20.49.104.48'] | []               | None             | True          | True             | False | ['TLSv1.2']      | DigiCert Inc     | []               | [22, 22]   | ['Washington,   |
|                  |                |                  |                  |                  |               |                  |       |                  |                  |                  |            | United States'] |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| gradeinflation.c | 1679270001.059 | ['51.79.45.180'] | []               | nginx            | True          | True             | False | ['TLSv1.2',      | Internet         | ['gw1.ahs5.r4l.c | [20, 20]   | ['Victoria,     |
| om               |                |                  |                  |                  |               |                  |       | 'TLSv1.3']       | Security         | om']             |            | Canada']        |
|                  |                |                  |                  |                  |               |                  |       |                  | Research Group   |                  |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| spacejam.com     | 1679270002.508 | ['99.83.180.228' | []               | Apache/2.4.55 () | True          | True             | True  | ['TLSv1.1',      | GlobalSign       | ['a259cf76d74e1f | [3, 3]     | ['United        |
|                  |                | ,                |                  | OpenSSL/1.0.2k-f |               |                  |       | 'TLSv1.2']       |                  | 65f.awsglobalacc |            | States']        |
|                  |                | '75.2.104.223']  |                  | ips              |               |                  |       |                  |                  | elerator.com', ' |            |                 |
|                  |                |                  |                  |                  |               |                  |       |                  |                  | a259cf76d74e1f65 |            |                 |
|                  |                |                  |                  |                  |               |                  |       |                  |                  | f.awsglobalaccel |            |                 |
|                  |                |                  |                  |                  |               |                  |       |                  |                  | erator.com']     |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| pmichaud.com     | 1679270006.696 | ['23.254.203.248 | []               | Apache           | True          | False            | False | ['TLSv1.2',      | Comodo CA        | ['hwsrv-233708.h | [26, 26]   | ['United        |
|                  |                | ']               |                  |                  |               |                  |       | 'TLSv1.3']       | Limited          | ostwindsdns.com' |            | States']        |
|                  |                |                  |                  |                  |               |                  |       |                  |                  | ]                |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+
| kli.org          | 1679270009.320 | ['20.127.141.51' | []               | LiteSpeed        | True          | True             | False | ['TLSv1.1',      | Internet         | []               | [22, 22]   | ['United        |
|                  |                | ]                |                  |                  |               |                  |       | 'TLSv1.2',       | Security         |                  |            | States']        |
|                  |                |                  |                  |                  |               |                  |       | 'TLSv1.3']       | Research Group   |                  |            |                 |
+------------------+----------------+------------------+------------------+------------------+---------------+------------------+-------+------------------+------------------+------------------+------------+-----------------+


+----------------------------+----------------+
|           Domain           | RTT Range (ms) |
+============================+================+
| it.eecs.northwestern.edu   | [2, 2]         |
+----------------------------+----------------+
| kellogg.northwestern.edu   | [2, 2]         |
+----------------------------+----------------+
| mccormick.northwestern.edu | [2, 2]         |
+----------------------------+----------------+
| users.cs.northwestern.edu  | [2, 2]         |
+----------------------------+----------------+
| northwestern.edu           | [3, 3]         |
+----------------------------+----------------+
| spacejam.com               | [3, 3]         |
+----------------------------+----------------+
| clocktab.com               | [3, 4]         |
+----------------------------+----------------+
| illinois.edu               | [6, 6]         |
+----------------------------+----------------+
| stevetarzia.com            | [12, 12]       |
+----------------------------+----------------+
| gradeinflation.com         | [20, 20]       |
+----------------------------+----------------+
| asee.org                   | [22, 22]       |
+----------------------------+----------------+
| kli.org                    | [22, 22]       |
+----------------------------+----------------+
| pmichaud.com               | [26, 26]       |
+----------------------------+----------------+
| uchicago.edu               | [26, 26]       |
+----------------------------+----------------+
| auditoryneuroscience.com   | [300, 300]     |
+----------------------------+----------------+


+----------------------------------+-----------+
|             Root CA              | Frequency |
+==================================+===========+
| Comodo CA Limited                | 6         |
+----------------------------------+-----------+
| Internet Security Research Group | 3         |
+----------------------------------+-----------+
| None                             | 2         |
+----------------------------------+-----------+
| Unspecified                      | 1         |
+----------------------------------+-----------+
| GlobalSign                       | 1         |
+----------------------------------+-----------+
| DigiCert Inc                     | 1         |
+----------------------------------+-----------+
| Baltimore                        | 1         |
+----------------------------------+-----------+


+------------------------------------------------------------+-----------+
|                         Webserver                          | Frequency |
+============================================================+===========+
| Apache                                                     | 3         |
+------------------------------------------------------------+-----------+
| nginx                                                      | 1         |
+------------------------------------------------------------+-----------+
| cloudflare                                                 | 1         |
+------------------------------------------------------------+-----------+
| None                                                       | 1         |
+------------------------------------------------------------+-----------+
| Microsoft-IIS/10.0                                         | 1         |
+------------------------------------------------------------+-----------+
| LiteSpeed                                                  | 1         |
+------------------------------------------------------------+-----------+
| BigIP                                                      | 1         |
+------------------------------------------------------------+-----------+
| Apache/2.4.55 () OpenSSL/1.0.2k-fips PHP/5.4.16            | 1         |
+------------------------------------------------------------+-----------+
| Apache/2.4.55 () OpenSSL/1.0.2k-fips                       | 1         |
+------------------------------------------------------------+-----------+
| Apache/2.4.52 (Ubuntu)                                     | 1         |
+------------------------------------------------------------+-----------+
| Apache/2.4.41 (Ubuntu)                                     | 1         |
+------------------------------------------------------------+-----------+
| Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k    | 1         |
+------------------------------------------------------------+-----------+
| Apache/2.2.15 (Red Hat) mod_ssl/2.2.15 OpenSSL/1.0.1e-fips | 1         |
+------------------------------------------------------------+-----------+


+-------------------+----------------------+
|      Feature      | Percentage Supported |
+===================+======================+
| TLSv1.0           | 26.667               |
+-------------------+----------------------+
| TLSv1.1           | 40.000               |
+-------------------+----------------------+
| TLSv1.2           | 86.667               |
+-------------------+----------------------+
| TLSv1.3           | 33.333               |
+-------------------+----------------------+
| insecure_http     | 100.000              |
+-------------------+----------------------+
| redirect_to_https | 86.667               |
+-------------------+----------------------+
| hsts              | 6.667                |
+-------------------+----------------------+
| ipv6_addresses    | 6.667                |
+-------------------+----------------------+
```

## Requirements
This code runs on Python 3.7+. Older versions may not be supported.
