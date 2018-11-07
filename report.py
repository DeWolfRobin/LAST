import json
import pdfkit


def generateReport():
    with open('merger.json') as file:
        jsondata = json.load(file)
    file = open('report.html', 'w')

    html = '''
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <title>Report</title>
                <meta charset="utf-8">
                <link rel="stylesheet" type="text/css" href="screen.css">
            </head>
        <body>
        '''

    for ip in jsondata:
        html += '<h1>%s</h1>' % ip

        for category in jsondata[ip]:
            html += '<div>'
            html += '<h2>%s</h2>' % category

            if(category == 'OS'):
                for os in jsondata[ip]['OS']:
                    html += '<p>%s</p>' % jsondata[ip]['OS'][os]
            elif (category == 'Ports'):
                html += '''
                    <table>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Service</th>
                        </tr>
                    '''

                for port, values in jsondata[ip]['Ports'].items():
                    html += '<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (port,
                                                                            values['protocol'], values['service'])
                html += '</table>'
            # TODO: add vulnerabilities to report (waiting for brian)
            html += '</div>'
    html += '</body></html>'

    file.write(html)
    file.close()

    css = 'screen.css'
    pdfkit.from_file('report.html', 'out.pdf', css=css)


def main():
    generateReport()


if __name__ == '__main__':
    main()
