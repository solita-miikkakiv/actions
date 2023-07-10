from copy import deepcopy
import io
import json
import datetime

def compare_ignored(ignored, found):
    ignored_full = []
    for i in ignored:
        # handle invalid lines
        if len(i.split(' ')) < 2:
            continue
        package = i.split(' ')[0]
        source = i.split(' ')[1]

        try:
            expires = i.split(' ')[2]
            current_time = datetime.datetime.now().timestamp()
            if int(expires) < int(current_time):
                continue
        except:
            expires = 0

        for id, data in found.items():
            if str(data['id']) == str(source) and data['module_name'] == package:
                data['expires'] = expires
                ignored_full.append(deepcopy(data))
                del found[id]
                break
                
    return found, ignored_full

def print_summary(vulns, ignored):
    if len(vulns) > 0:
        for id, i in vulns.items():
            print(f"{i['module_name']} {i['vulnerable_versions']}")
            print(f"Severity: {i['severity']}")
            try:
                print(f"{i['title']} {i['url']}")
            except:
                print(f"{i['cwe']}")
            print(f"Fix: {i['recommendation']}")
            print(f"Effects: {i['findings']}\n")
            print(f"('{i['module_name']} {str(i['id'])} <expiration-date-in-seconds-optional>' to ignore)\n")

    if len(ignored) > 0:
        for i in ignored:
            try:
                expires = datetime.datetime.fromtimestamp(int(i["expires"])).strftime('%Y-%m-%d %H:%M:%S')
                if int(i["expires"]) == 0:
                    expires = "never"
            except:
                expires = "never"
            print(f"(IGNORED: expires {expires}) {i['module_name']} {i['vulnerable_versions']}")
            print(f"Severity: {i['severity']}")
            print(f"{i['cwe']}")
            print(f"Fix: {i['recommendation']}")
            print(f"Effects: {i['findings']}\n")


with open('audit.json', 'r') as f:
    file = f.read()

try:
    data = json.loads(file)
except:
    # yarn produces utf-16 encoded json in some environments
    with io.open('audit.json', 'r', encoding="utf-16") as f:
        file = f.read()
    data = json.loads(file)

vulns = data['advisories']

try:
    with open('.yarnauditignore', 'r') as f:
        ignorefile = f.read()
        ignore_list = ignorefile.split('\n')
except:
    ignore_list = []

not_ignored, ignore_info = compare_ignored(ignore_list, vulns)

if len(not_ignored) > 0:
    print('Vulnerabilities found:\n')
    print_summary(not_ignored, ignore_info)
    print(f"Vulnerabilities: {len(vulns)} ({len(ignore_info)} vulnerabilities ignored)")
    exit(1)
else:
    print('No vulnerabilities found.\n')
    print_summary(not_ignored, ignore_info)
    print(f"Vulnerabilities: {len(vulns)} ({len(ignore_info)} vulnerabilities ignored)")
    exit(0)