import texttable
import json
import sys

def percent_tables(data):
    t = texttable.Texttable(200)
    t.header(["Feature", "Percentage Supported"])
    t.set_cols_dtype(["t", "f"])

    n = 0

    #Key, Freq
    tls_freq = {}
    insecure = 0
    https_red = 0
    hsts = 0
    ipv6 = 0

    for website in data:
        n += 1
        web_stats = data[website]
        for scans, fields in web_stats.items():
            if scans == "tls_versions":
                for tls_versions in fields:
                    if tls_versions not in tls_freq:
                        tls_freq[tls_versions] = 1
                    else:
                        tls_freq[tls_versions] += 1

            elif scans == "insecure_http":
                if fields == True:
                    insecure += 1

            elif scans == "redirect_to_https":
                if fields == True:
                    https_red += 1

            elif scans == "hsts":
                if fields == True:
                    hsts += 1

            elif scans == "ipv6_addresses":
                if fields:
                    ipv6 += 1



    for key, value in tls_freq.items():
        t.add_row([key, str(float(100*value/n))])
    t.add_row(["insecure_http", str(float(100*insecure/n))])
    t.add_row(["redirect_to_https", str(float(100 * https_red/n))])
    t.add_row(["hsts", str(float(100 * hsts / n))])
    t.add_row(["ipv6_addresses", str(float(100 * ipv6 / n))])

    return t.draw()


def freq_tables(data):
    t = texttable.Texttable(200)
    t.header(["Root CA", "Frequency"])

    webtable = texttable.Texttable(200)
    webtable.header(["Webserver", "Frequency"])

    #Key, Freq
    ca_freq = {}
    webserv_freq = {}

    for website in data:
        web_stats = data[website]
        for scans, fields in web_stats.items():
            if scans == "root_ca":
                if fields == None:
                    fields = "None"

                if fields not in ca_freq:
                    ca_freq[fields] = 1
                else:
                    ca_freq[fields] += 1

            elif scans == "http_server":
                if fields == None:
                    fields = "None"
                if fields not in webserv_freq:
                    webserv_freq[fields] = 1
                else:
                    webserv_freq[fields] += 1

    ca_freq = sorted(ca_freq.items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    webserv_freq = sorted(webserv_freq.items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    for tuple in ca_freq:
        t.add_row([tuple[0], tuple[1]])
    for tuple in webserv_freq:
        webtable.add_row([tuple[0], tuple[1]])

    return t.draw() + "\n\n\n" + webtable.draw() + "\n\n\n"


def rtt_table(data):
    t = texttable.Texttable(200)
    t.header(["Domain", "RTT Range (ms)"])

    master_rows = []
    for website in data:
        try:
            rtt = data[website]["rtt_range"]
        except:
            pass
        if rtt == None:
            continue
        row = [website, rtt]
        master_rows.append(row)

    sorted_data = sorted(master_rows, key=lambda kv: (kv[1], kv[0]))
    for row in sorted_data:
        t.add_row(row)

    return t.draw() + "\n\n\n"


def domain_table(data):
    t = texttable.Texttable(225)

    t.set_cols_dtype(["t",  # domain
                      "f",  # scan_time
                      "t",  # ipv4_addresses: longer
                      "t",  # ipv6_addresses: longer
                      "t",  # http_server
                      "t",  # insecure_http
                      "t",  # redirect_to_https
                      "t",  # hsts
                      "t",  # tls versions
                      "t",  # root_ca: longer
                      "t",  # rdns_names: longer!
                      "t",  # rtt_range: shorter
                      "t",  # geo_locations: longer
                      ])

    header = ["domain", "scan_time", "ipv4_addresses", "ipv6_addresses", "http_server", "insecure_http", "redirect_to_https", "hsts", "tls_versions", "root_ca", "rdns_names", "rtt_range", "geo_locations"]
    t.header(header)

    for website in data:
        web_stats = data[website]
        row = [website]

        for x in header[1:13]:
            scans = web_stats

            if x in scans:
                fields = scans[x]
            else:
                fields = "None"

            row.append(fields)
        t.add_row(row)

    return t.draw() + "\n\n\n"


def main(in_file, out_file):
    with open(in_file) as f:
        data = json.load(f)
        f.close()

    with open(out_file, "w") as o:
        o.write(domain_table(data))
        o.write(rtt_table(data))
        o.write(freq_tables(data))
        o.write(percent_tables(data))
        o.close()

#.json -> .txt
in_file = sys.argv[1]
out_file = sys.argv[2]

main(in_file, out_file)
