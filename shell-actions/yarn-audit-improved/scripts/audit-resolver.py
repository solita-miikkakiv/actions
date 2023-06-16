from copy import deepcopy
import json
import datetime

def getAdvisories(data):
    vulns = []
    for i in data:
        if i['type'] == 'auditAdvisory':
            vulns.append(i['data'])
    return vulns

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

        for j in found:
            if str(j['advisory']['id']) == str(source) and j['advisory']['module_name'] == package:
                j['expires'] = expires
                ignored_full.append(deepcopy(j))
                found.remove(j)
                break
                
    return found, ignored_full

def print_summary(vulns, ignored):
    if len(vulns) > 0:
        for i in vulns:
            print(f"{i['advisory']['module_name']} {i['advisory']['vulnerable_versions']}")
            print(f"Severity: {i['advisory']['severity']}")
            print(f"{i['advisory']['title']} {i['advisory']['url']}")
            print(f"Fix: {i['advisory']['recommendation']}")
            print(f"Effects: {i['advisory']['findings']}\n")
            print(f"('{i['advisory']['module_name']} {str(i['advisory']['id'])} <expiration-date-in-seconds-optional>' to ignore)\n")

    if len(ignored) > 0:
        for i in ignored:
            try:
                expires = datetime.datetime.fromtimestamp(int(i["expires"])).strftime('%Y-%m-%d %H:%M:%S')
                if int(i["expires"]) == 0:
                    expires = "never"
            except:
                expires = "never"
            print(f"(IGNORED: expires {expires}) {i['advisory']['module_name']} {i['advisory']['vulnerable_versions']}")
            print(f"Severity: {i['advisory']['severity']}")
            print(f"{i['advisory']['title']} {i['advisory']['url']}")
            print(f"Fix: {i['advisory']['recommendation']}")
            print(f"Effects: {i['advisory']['findings']}\n")


with open('audit.json', 'r') as f:
    file = f.read()


file = file.replace('}{', '},{')
file = file.replace('}\n{', '},\n{')
print('[' + file + ']')
data = json.loads('[' + file + ']')

vulns = getAdvisories(data)

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