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
        expires = i["expires"] if i["expires"] else "never"
        if expires != "never": 
            expires = datetime.datetime.fromtimestamp(int(expires) / 1000).strftime('%Y-%m-%d %H:%M:%S')
        print(f"(IGNORED: expires {expires}) {i['via'][0]['name']} {i['range']}")
        print(f"Severity: {i['severity']}")
        print(f"{i['via'][0]['title']} {i['via'][0]['url']}")
        print(f"Fix available: {str(i['fixAvailable'] != False)}")
        print(i['nodes'])
        print(f"Effects: {str(i['effects'])}\n")


f = open('audit.json', 'r').read()
print(f)

data = json.loads(f)

vulns = data['vulnerabilities']

vulns_with_source = []

for i in vulns:
    via = vulns[i]['via']
    if type(via[0]) == dict:
        vulns_with_source.append(vulns[i])

try:
    ignorefile = open('.npmauditignore', 'r').read()
    ignore_list = ignorefile.split('\n')
except:
    ignore_list = []

not_ignored, ignore_info = compare_ignored(ignore_list, vulns_with_source)

if len(not_ignored) > 0:
    print('Vulnerabilities found:\n')
    print_summary(not_ignored, ignore_info)
    exit(1)
else:
    print('No vulnerabilities found.\n')
    print_summary(not_ignored, ignore_list)
    exit(0)

