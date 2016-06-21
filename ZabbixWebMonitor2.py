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


def getiddict(dictname1):
    """Pulls all hostids and names from the Zabbix server and creates a dictionary mapping names to ids."""
    if isinstance(dictname1, dict):
        try:
            for h in z.host.get(output="extend"):
                dictname1[h['name']] = h['hostid']
        except ZabbixAPIException as error:
            print(error)
    else:
        print("Must pass dict variable.")
        sys.exit(2)
    return


def getgroupdict(dictname):
    """Pulls all group ids and names from the Zabbix server and creates a dictionary mapping names to ids.

    Sets default group to add hosts, starting with a hierarchy of common names then moving to specifying
    or creating a new group.
    """
    if isinstance(dictname, dict):
        try:
            for g in z.hostgroup.get(output="extend"):
                dictname[g['name']] = g['groupid']
        except ZabbixAPIException as error:
            print(error)
        if "Web Hosts" in dictname.keys():
            default['groupid'] = dictname['Web Hosts']
        elif "Web hosts" in dictname.keys():
            default['groupid'] = dictname['Web hosts']
        elif "Discovered hosts" in dictname.keys():
            default['groupid'] = dictname['Discovered hosts']
        else:
            newgroup = input("Default group for new hosts:")
            if newgroup in dictname.keys():
                default['groupid'] = dictname[newgroup]
            else:
                print("Create this group?", newgroup)
                x = 1
                while x == 1:
                    yesno = input("y/n:")
                    if yesno == 'y' or yesno == 'yes' or yesno == 'Y' or yesno == 'Yes':
                        if creategroup(newgroup):
                            try:
                                for k in z.hostgroup.get(output="extend"):
                                    if k['name'] == newgroup:
                                        default['groupid'] = k['groupid']
                            except ZabbixAPIException as error1:
                                print(error1)
                    elif yesno == 'n' or yesno == 'no' or yesno == 'N' or yesno == 'No':
                        sys.exit(3)
    else:
        print("Must pass dict variable.")
        sys.exit(2)
    return


def idschange(listname, dictname):
    """Replaces host name in a nested list with hostid.

    A recursive function used to examine and change the base list in a nested-list structure.
    Replaces host name with host id using a dictionary constructed by getiddict().
    """
    for index, item in enumerate(listname):
        if isinstance(item, list):
            idschange(item, dictname)
        elif item in dictname.keys():
            existinghostname.append(item)
            listname[index] = dictname[item]
            existinghostid.append(dictname[item])
    return


def groupidschange(listname, dictname):
    for index, item in enumerate(listname):
        if isinstance(item, list):
            groupidschange(item, dictname)
        elif item in dictname.keys():
            listname[index] = dictname[item]


def getopenfilepath():
    """Uses the tk module to ask for the filename and path of the CSV file to be parsed."""
    root = tk.Tk
    return filedialog.askopenfilename(initialdir='C:/', filetypes=[('Comma Separated Values (.csv)', '.csv')])


def readcsvfile(listname):
    """Parses the CSV file and determines if it has a header."""
    with open(getopenfilepath(), 'r', newline='') as result:
        dialect = csv.Sniffer().sniff(result.read(2048))
        result.seek(0)
        arbitrary = csv.Sniffer().has_header(result.read(2048))
        result.seek(0)
        reader = csv.reader(result, dialect=dialect)
        for row in reader:
            listname.append(row)
    return arbitrary


def validatewithheader(listname):
    """Checks to see if the CSV header matches the default header. Prepares dictionaries to be written to server."""
    error = False
    ids = {}
    groupids = {}
    data = []
    header = listname[0]
    defaultheader = list(default.keys())
    if sorted(defaultheader) == sorted(header):
        content = listname[1:]
        getiddict(ids)
        getgroupdict(groupids)
        idschange(content, ids)
        groupidschange(content, groupids)
        rowcount1 = 0
        for row in content:
            rowcount1 += 1
            datarow = dict(zip(header, row))
            if datarow['hostid'] not in existinghostid:
                newhost.append(datarow['hostid'])
            for key in datarow.keys():
                if datarow[key] == '':
                    datarow[key] = default[key]
                if datarow[key] == 'Required':
                    print("Required attribute not found in row", str(rowcount1 + 1) + ':', key)
                    error = True
            data.append(datarow)
        else:
            if error:
                sys.exit(2)
            else:
                print(rowcount1, "record(s) loaded.\nNew hosts:")
                for i in newhost:
                    print(i)
                print("Existing hosts:")
                for j in existinghostname:
                    print(j)
                print("Ready to write to Zabbix Server?")
                x = 1
                while x == 1:
                    yesno = input("y/n:")
                    if yesno == 'y' or yesno == 'yes' or yesno == 'Y' or yesno == 'Yes':
                        return data
                    elif yesno == 'n' or yesno == 'no' or yesno == 'N' or yesno == 'No':
                        sys.exit(3)
    else:
        print("Header mismatch. Please ensure .csv header matches the header configured in this file.")
        print(sorted(defaultheader))
        sys.exit(2)


def creategroup(groupname):
    try:
        z.hostgroup.create(name=groupname)
    except ZabbixAPIException as error:
        print("Error creating group:\n", error)
        return False
    else:
        return True


def createhost(datacon):
    for record in datacon:
        data = record
        try:
            z.host.create(
                host=data['*name'],
                group=[{
                    'groupid': data['groupid']
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
            print("Error creating host", data['*name'], ':\n', error)


def writewebrecord(datacon):
    """Creates a new web scenario for in the Zabbix server for each row read out of the CSV file."""
    for record in datacon:
        data = record
        try:
            z.httptest.create(
                name=data['*name'],
                hostid=data['hostid'],
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
                steps= [{
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
            print(data["*name"], "created.")
        except ZabbixAPIException as error:
            print("Error creating web scenario", data["*name"], ":\n", error)
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
        # CHANGE to reflect default group for server that the script is run on.
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
    hostlist = []
    existinghostid = []
    existinghostname = []
    newhost = []
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
    rowcount1 = 0
    if readcsvfile(hostlist):
        for row1 in hostlist:
            rowcount1 += 1
        if rowcount1 == 1:
            print("The imported CSV file must have a header.\nDefault header:")
            print(sorted(default.keys()))
            sys.exit(2)
        else:
            datalist = validatewithheader(hostlist)
            if len(newhost) > 0:
                createhost(datalist)
                writewebrecord(datalist)
            else:
                writewebrecord(datalist)
    else:
        print("The imported CSV file must have a header.\nDefault header:")
        print(sorted(default.keys()))
        sys.exit(2)
