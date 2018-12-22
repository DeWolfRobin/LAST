import json
import pdfkit


def generate_report():
    json_file = 'output/master.json'
    html_file = 'output/report.html'
    pdf_file = 'output/report.pdf'

    with open(json_file) as file:
        jsondata = json.load(file)
    file = open(html_file, 'w')

    html = '''
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <title>Report</title>
                <meta charset="utf-8">
                <link rel="stylesheet" type="text/css" href="screen.css">
                <script src="jquery.js"></script>
                <script src="script.js"></script>
            </head>
        <body>
        <h1>Report</h1>
        '''

    html += '<h2>Summary</h2>'
    jsonsummary = jsondata["Summary"]
    html += generate_summary(jsonsummary)
    try:
        html += generate_searchsploit()
    except:
        html = html
    try:
        html += generate_nbt()
    except:
        html = html

    html += '<h2>Details</h2>'
    jsondetails = jsondata["Details"]
    html += generate_details(jsondetails)

    html += '</body></html>'

    file.write(html)
    file.close()

    pdfkit.from_file(html_file, pdf_file)


def generate_details(jsondetails):
    html = ''

    for ip in jsondetails:
        html += '<h3>%s</h3>' % ip

        for category in jsondetails[ip]:
            html += '<h4>%s</h4>' % category

            if category == 'OS':
                if not jsondetails[ip][category]:
                    html += '<p>Failed to recognize Operating System</p>'
                else:
                    for os in jsondetails[ip][category]:
                        html += '<p>%s</p>' % jsondetails[ip][category][os]
            if category == 'Ports':
                html += '''
                    <table>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Service</th>
                        </tr>
                    '''
                for port, values in jsondetails[ip][category].items():
                    html += '<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                        port, values['protocol'], values['service'])
                html += '</table>'
            if category == 'Vulnerabilities':
                for vulncategory in jsondetails[ip][category]:
                    if 'Nessus-Severity' in vulncategory:
                        if type(jsondetails[ip][category][vulncategory]) == "undefined":
                            html += '<h5>%s</h5>' % vulncategory
                        html += '<ul>'
                        for vuln in jsondetails[ip][category][vulncategory]:
                            html += '<li>%s: %s</li>' % (
                                vuln, jsondetails[ip][category][vulncategory][vuln])
                        html += '</ul>'
                    else:
                        html += '<ul>'
                        for vuln in jsondetails[ip][category][vulncategory]['Nmap-Vuln']:
                            html += '<li>%s: %s</li>' % (
                                vuln, jsondetails[ip][category][vulncategory]['Nmap-Vuln'][vuln])
                        html += '</ul>'
        try:
            html += generate_enum4linux(ip)
        except:
            html = html
        try:
            html += generate_snmp(ip)
        except:
            html = html
    return html

def generate_enum4linux(host):
    try:
        html = ''

        html += '<h4>enum4linux</h4>'
        html += '<pre>'
        enum_file = 'output/enum/enum-%s.txt' % host
        with open(enum_file, 'r') as file:
            html += '%s' % file.read()
        html += '</pre>'

        return html
    except:
        return ""

def generate_searchsploit():
    try:
        html = ''

        html += '<h3>Verified by SearchSploit</h3>'
        html += '<pre>'
        searchsploit_file = 'output/searchsploit'
        with open(searchsploit_file, 'r') as file:
            html += '%s' % file.read()
        html += '</pre>'

        return html
    except:
        return ""

def generate_snmp(host):
    try:
        html = ''

        html += '<h4>SNMPAutoEnum by Tijl Deneut</h4>'
        html += '<pre>'
        r_file = 'output/snmp/%s.txt' % host
        with open(r_file, 'r') as file:
            html += '%s' % file.read()
        html += '</pre>'

        return html
    except:
        return ""

def generate_nbt():
    try:
        html = ''

        html += '<h3>Net-BIOS names</h3>'
        html += '<pre>'
        r_file = 'output/nbt.txt'
        with open(r_file, 'r') as file:
            html += '%s' % file.read()
        html += '</pre>'

        return html
    except:
        return ""

def generate_summary(jsonsummary):
    html = ''

    html += '<small>&gt; Hosts found: <b>%s</b></small>' % jsonsummary['Amount of Hosts']

    for category in jsonsummary['Vulnerabilities found']:
        html += '<h3>%s</h3>' % category

        if category == 'CVE':
            html += '<ul>'
            for cve in jsonsummary['Vulnerabilities found']['CVE']:
                html += '<li>%s</li>' % cve
            html += '</ul>'
        if category == 'Uncategorised':
            html += '<ul>'
            for vuln in jsonsummary['Vulnerabilities found']['Uncategorised']:
                html += '<li>%s : %s</li>' % (
                    vuln, jsonsummary['Vulnerabilities found']['Uncategorised'][vuln])
            html += '</ul>'
        if 'Nessus-Severity' in category:
            html += '<ul>'
            for ip in jsonsummary['Vulnerabilities found']['Nessus-Severity-4']:
                html += '<li>%s vulnerabilities found on host %s</li>' % (
                    jsonsummary['Vulnerabilities found']['Nessus-Severity-4'][ip], ip)
            html += '</ul>'

    return html


def main():
    generate_report()


if __name__ == '__main__':
    main()
