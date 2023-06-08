from copy import deepcopy
import json
import datetime
import io

def compare_ignored(ignored, found):
    ignored_full = []
    for i in ignored:
        package = i.split(' ')[0]
        source = i.split(' ')[1]

        try:
            expires = i.split(' ')[2]
            current_time = datetime.datetime.now().timestamp() * 1000
            if int(expires) < int(current_time):
                continue
        except:
            expires = 0

        for j in found:
            if str(j['via'][0]['source']) == str(source) and j['via'][0]['name'] == package:
                j["expires"] = expires
                ignored_full.append(j)
                found.remove(j)
    return found, ignored_full

def print_summary(vulns, ignored):
    for i in vulns:
        print(f"{i['via'][0]['name']} {i['range']}")
        print(f"Severity: {i['severity']}")
        print(f"{i['via'][0]['title']} {i['via'][0]['url']}")
        print(f"Fix available: {str(i['fixAvailable'] != False)}")
        print(i['nodes'])
        print(f"Effects: {str(i['effects'])}\n")
        print(f"('{i['via'][0]['name']} {str(i['via'][0]['source'])} <expiration-date-in-millis-optional>' to ignore)\n")

    for i in ignored:
        try:
            expires = datetime.datetime.fromtimestamp(int(i["expires"]) / 1000).strftime('%Y-%m-%d %H:%M:%S')
        except:
            expires = "never"
        # print(f"(IGNORED: expires {expires}) {i['via'][0]['name']} {i['range']}")
        print(f"(IGNORED: expires {expires}) {i['range']}")
        print(f"Severity: {i['severity']}")
        print(f"{i['via'][0]['title']} {i['via'][0]['url']}")
        print(f"Fix available: {str(i['fixAvailable'] != False)}")
        print(i['nodes'])
        print(f"Effects: {str(i['effects'])}\n")


f = open('audit.json', 'r').read()

try:
    data = json.loads(f)
except:
    # npm produces utf-16 encoded json in some environments
    f = io.open('audit.json', 'r', encoding="utf-16").read()
    data = json.loads(f)

vulns = data['vulnerabilities']

vulns_with_source = []

for i in vulns:
    via = vulns[i]['via']
    for j in via:
        if type(j) == dict:
            vuln_atom = vulns[i]
            vuln_atom["severity"] = j['severity']
            vuln_atom["via"] = [j]
            vulns_with_source.append(deepcopy(vuln_atom))

try:
    ignorefile = open('.npmauditignore', 'r').read()
    ignore_list = ignorefile.split('\n')
except:
    ignore_list = []

not_ignored, ignore_info = compare_ignored(ignore_list, vulns_with_source)

if len(not_ignored) > 0:
    print('Vulnerabilities found:\n')
    print_summary(not_ignored, ignore_info)
    print(f"Total vulnerabilities: {len(vulns)} ({len(ignore_info)} ignored)")
    exit(1)
else:
    print('No vulnerabilities found.\n')
    print_summary(not_ignored, ignore_list)
    print(f"Total vulnerabilities: {len(vulns)} ({len(ignore_info)} ignored)")
    exit(0)

