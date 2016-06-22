import sys
import datetime
import csv
import re
import requests
import tkinter as tk
from tkinter import filedialog
from pyzabbix import ZabbixAPI, ZabbixAPIException
import logging


def initializeapi():
    """Initializes the Zabbix API connection and logs the user in.

    Checks that username and password are strings. Login exceptions handled by pyzabbix.
    serverip must be the full url of the server (eg. http://192.168.0.7/zabbix)
    """
    tries = 4
    while tries >= 0:
        user = input("Zabbix username:")
        password = input("Zabbix password:")
        if isinstance(user, str) == True and isinstance(password, str) == True:
            try:
                z.login(user=user, password=password)
                print("Logged into ZabbixAPI version " + z.api_version() + ".")
                return True
            except ZabbixAPIException as error:
                print(error)
                tries -= 1
            except requests.Timeout as f:
                print(f, "\nProgram will now exit.")
                sys.exit(2)
            except requests.HTTPError as g:
                print(g, "\nProgram will now exit.")
                sys.exit(2)
        else:
            print("Username and password must be strings.")
    else:
        print("Too many failed login attempts.")
        return False


def validateserver(server):
    """Checks for 'http://' and 'zabbix' in the serverip to validate the URL.

    Alternatively checks for 'https://' and 'zabbix' for secured connections. This function does not verify the
    existence of the server, only that the correct convention was followed when typing in the address.
    """
    if re.search('http://', server) and re.search('zabbix', server):
        return True
    elif re.search('https://', server) and re.search('zabbix', server):
        return True
    else:
        return False


def readcsvfile(listname):
    """Parses the CSV file and determines if it has a header, then imports it row by row."""
    with open(getopenfilepath(), 'r', newline='') as result:
        dialect = csv.Sniffer().sniff(result.read(2048))
        result.seek(0)
        arbitrary = csv.Sniffer().has_header(result.read(2048))
        result.seek(0)
        reader = csv.reader(result, dialect=dialect)
        for row in reader:
            listname.append(row)
    return arbitrary


def getopenfilepath():
    """Uses the tk module to ask for the filename and path of the CSV file to be parsed."""
    root = tk.Tk
    return filedialog.askopenfilename(initialdir='C:/', filetypes=[('Comma Separated Values (.csv)', '.csv')])


def getgroupdict(dictname):
    """Pulls all group ids and names from the Zabbix server and makes a dictionary mapping names to ids."""
    try:
        for g in z.hostgroup.get(output='extend'):
            dictname[g['name']] = g['groupid']
    except ZabbixAPIException as error:
        print("Error retrieving host groups:\n", error)
        sys.exit(2)


def defaultgroup(dictname):
    """Sets the default group that new hosts will be added to when they are created.

    First prints the groups available on the server, then asks the user to enter the group they wish to be the default.
    If it does not exist, asks the user if the wish to create the group.
    """
    retry = 3
    print('Available groups:')
    for key in dictname.keys():
        print(key)
    while retry >= 0:
        group = input("Enter default hostgroup:")
        if group in dictname.keys():
            default['groupid'] = group
            return
        else:
            print("Hostgroup not found on server. Create new hostgroup?")
            x = 1
            while x == 1:
                yesno = input("y/n:")
                if yesno == 'y' or yesno == 'yes' or yesno == 'Y' or yesno == 'Yes':
                    createhostgroup(group)
                    print('Host group', group, 'created successfully.')
                    getgroupdict(dictname)
                    default['groupid'] = group
                    return
                elif yesno == 'n' or yesno == 'no' or yesno == 'N' or yesno == 'No':
                    retry -= 1
                    break
    else:
        print("Exceeded permitted number of retries.")
        sys.exit(2)


def createhostgroup(groupname):
    try:
        z.hostgroup.create(name=str(groupname))
    except ZabbixAPIException as error:
        print("Error creating group:\n", error)
        sys.exit(2)


def getiddict(dictname):
    """Pulls all hostids and names from the Zabbix server and creates a dictionary mapping names to ids."""
    if isinstance(dictname, dict):
        for h in z.host.get(output="extend"):
            dictname[h['name']] = h['hostid']
    else:
        print("Must pass dict variable.")
        sys.exit(2)
    return


def validatewithheader(listname):
    """Checks to see if the CSV header matches the default header. Prepares dictionaries to be written to server."""
    header = listname[0]
    defaultheader = list(default.keys())
    if sorted(defaultheader) == sorted(header):
        return
    else:
        print("Header mismatch. Please ensure .csv header matches the header configured in this file.")
        print(sorted(defaultheader))
        sys.exit(2)


def validateinputs(listname):
    data1 = []
    error = False
    rowcount = 0
    header = listname[0]
    for row in listname[1:]:
        rowcount += 1
        datarow = dict(zip(header, row))
        for key in datarow.keys():
            if datarow[key] == '':
                datarow[key] = default[key]
            if datarow[key] == 'Required':
                print("Required attribute missing in row", str(rowcount + 1) + ':', key)
                error = True
        data1.append(datarow)
        if datarow['groupid'] not in groupdict.keys():
            error = True
            print("Incorrect group in row", str(rowcount + 1))
    else:
        if error:
            sys.exit(2)
        else:
            return data1


def checkhosts(datadict):
    for record in datadict:
        if record['hostid'] in iddict.keys():
            existinghosts.append(record)
        else:
            newhosts.append(record)
    return


def createnewhosts():
    for h in newhosts:
        try:
            z.host.create(
                host=h['hostid'],
                groups=[{
                    'groupid': groupdict[h['groupid']]
                }],
                interfaces=[{
                    'type': '1',
                    'main': '1',
                    'useip': '1',
                    'ip': '127.0.0.1',
                    'dns': '',
                    'port': '10050'
                }]
            )
        except ZabbixAPIException as error:
            print("Error creating host:", h['hostid'], '\n', error)
        else:
            print("New host  '" + str(h['hostid']) + "' successfully created.")


def writewebrecord(datacon):
    """Creates a new web scenario for in the Zabbix server for each row read out of the CSV file."""
    for record in datacon:
        data = record
        try:
            z.httptest.create(
                name=data['*name'],
                hostid=iddict[data['hostid']],
                delay=data['delay'],
                agent=data['agent'],
                headers=data['*headers'],
                variables=data['*variables'],
                authentication=data['authentication'],
                http_user=data['http_user'],
                http_password=data['http_password'],
                ssl_cert_file=data['ssl_cert_file'],
                ssl_key_file=data['ssl_key_file'],
                ssl_key_password=data['ssl_key_password'],
                verify_host=data['verify_host'],
                verify_peer=data['verify_peer'],
                steps=[{
                    'no': int(data['no']),
                    'name': data['name'],
                    'url': data['url'],
                    'posts': data['posts'],
                    'variables': data['variables'],
                    'headers': data['headers'],
                    'follow_redirects': data['follow_redirects'],
                    'timeout': data['timeout'],
                    'required': data['required'],
                    'status_codes': data['status_codes']
                }]
            )
            print("Web scenario '" + str(data["*name"]) + "' created.")
        except ZabbixAPIException as error:
            print("Error creating web scenario '" + str(data["*name"]) + "':\n", error)
        except KeyError as error:
            print("Error creating web scenario: host does not exist.\n", error)
        else:
            try:
                z.trigger.create(
                    description=data['*name'] + " failed: {ITEM.VALUE}",
                    expression='{' + data['hostid'] + ":web.test.fail[" + data['*name'] + "].last()}>0 and " + \
                               '{' + data['hostid'] + ":web.test.error[" + data['*name'] + "].strlen()}<>0",
                    comment=data['hostid'] + ":web.test.error[" + data['*name'] + "]}",
                    priority='4',
                    url='http://{$MYIP}/zabbix/events.php?triggerid={TRIGGERID}&filter_set=1&time=86400'
                )
            except ZabbixAPIException as error2:
                print("Error creating trigger:\n", error2)
            else:
                print("Availability trigger for '" + str(data['*name']) + "' created.")
    else:
        print("Complete.")


if __name__ == '__main__':
    # Code for enabling logging output for pyzabbix in python console:
    # stream = logging.StreamHandler(sys.stdout)
    # stream.setLevel(logging.DEBUG)
    # Code to write logs to a file in the directory where the script runs
    file = logging.FileHandler("WebMonitorImport_" + datetime.datetime.now().strftime("%Y-%m%d-%H%M") + '.log',
                               mode='w')
    file.setLevel(logging.DEBUG)
    log = logging.getLogger('pyzabbix')
    # log.addHandler(stream)
    log.addHandler(file)
    log.setLevel(logging.DEBUG)
    default = {
        'hostid': 'Required',
        'groupid': 'Required',
        '*name': 'Required',
        'delay': '60',
        'retries': '1',
        'agent': 'Zabbix',
        '*headers': '',
        '*variables': '',
        'authentication': '0',
        'http_user': '',
        'http_password': '',
        'ssl_cert_file': '',
        'ssl_key_file': '',
        'ssl_key_password': '',
        'verify_host': '0',
        'verify_peer': '0',
        'no': 'Required',
        'name': 'Required',
        'url': 'Required',
        'posts': '',
        'variables': '',
        'headers': '',
        'follow_redirects': '1',
        'timeout': '15',
        'required': '',
        'status_codes': ''
    }
    retries = 4
    list1 = []
    groupdict = {}
    iddict = {}
    rowcount1 = 0
    newhosts = []
    existinghosts = []
    while retries >= 0:
        serverip = input("URL of zabbix server:")
        if validateserver(serverip):
            timeout = 3.5
            try:
                z = ZabbixAPI(str(serverip), timeout=timeout)
            except ZabbixAPIException as e:
                print(e)
            if initializeapi():
                break
        elif retries > 0:
            retries -= 1
        else:
            print("Too many failed attempts.")
            sys.exit(2)
    if readcsvfile(list1):
        rowcount1 = len(list1)
        if rowcount1 <= 1:
            print("The imported CSV file must have a header.\nDefault header:")
            print(sorted(default.keys()))
            sys.exit(2)
        else:
            # Main function block
            getiddict(iddict)
            getgroupdict(groupdict)
            defaultgroup(groupdict)
            validatewithheader(list1)
            data2 = validateinputs(list1)
            checkhosts(data2)
            print(str(len(data2)), "records loaded.\nExisting hosts:")
            for i in existinghosts:
                print('Host:   ', i['hostid'], '   Group:   ', i['groupid'], '   Scenario:   ', i['*name'])
            print("New hosts:")
            for j in newhosts:
                print('Host:   ', j['hostid'], '   Group:   ', j['groupid'], '   Scenario:   ', j['*name'])
            print("Ready to write to Zabbix server?")
            y = 1
            while y == 1:
                ask = input("y/n:")
                if ask == 'y' or ask == 'yes' or ask == 'Y' or ask == 'Yes':
                    createnewhosts()
                    getiddict(iddict)
                    writewebrecord(data2)
                    break
                elif ask == 'n' or ask == 'no' or ask == 'N' or ask == 'No':
                    print("Write aborted.")
                    sys.exit(3)
    else:
        print("The imported CSV file must have a header.\nDefault header:")
        print(sorted(default.keys()))
        sys.exit(2)