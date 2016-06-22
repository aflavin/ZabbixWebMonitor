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


def gethttptestdict(dictname):
    if isinstance(dictname, dict):
        try:
            for test in z.httptest.get(output='extend'):
                dictname[(hostdict[test['hostid']], test['name'])] = test['httptestid']
        except KeyError as kerror:
            print(kerror)
    else:
        print("Must pass dict variable.")
        sys.exit(2)
    return


def gethostdict(dictname):
    """Pulls all hostids and names from the Zabbix server and creates a dictionary mapping ids to names."""
    if isinstance(dictname, dict):
        for h in z.host.get(output="extend"):
            dictname[h['hostid']] = h['name']
    else:
        print("Must pass dict variable.")
        sys.exit(2)
    return


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


def validateinput(listname):
    data1 = []
    error = False
    rowcount = 0
    for datarow in listname:
        rowcount += 1
        for key in datarow.keys():
            if datarow[key] == '':
                datarow[key] = default[key]
            if datarow[key] == 'Required':
                print("Required attribute missing in row", str(rowcount + 1) + ':', key)
                error = True
        data1.append(datarow)
        if (datarow['hostid'], datarow['*name']) not in httpdict.keys():
            error = True
            print("Scenario not found on host", datarow['hostid'], datarow['*name'])
    else:
        if error:
            sys.exit(2)
        else:
            return data1


def retrievalfill(listname):
    data1 = []
    rowcount = 0
    header = listname[0]
    for row in listname[1:]:
        rowcount += 1
        datarow = dict(zip(header, row))
        if (datarow['hostid'], datarow['*name']) in httpdict.keys():
            try:
                retrieve = z.httptest.get(httptestids=httpdict[(datarow['hostid'], datarow['*name'])],
                                            output='extend', selectSteps='extend')
                for thing in retrieve:
                    for key in datarow.keys():
                        if datarow[key] == '' and key == 'delay' or key == 'http_user' or key == "http_password":
                            datarow[key] = thing[key]
                        elif datarow[key] == '':
                            step = thing['steps']
                            step1 = step[0]
                            datarow[key] = step1[key]
            except ZabbixAPIException as error:
                print(error)
        else:
            print("Web scenario not found on host", datarow['hostid'], datarow['*name'])
        data1.append(datarow)
    return data1


def httpupdate(data):
    for record in data:
        try:
            z.httptest.update(
                httptestid=httpdict[(record['hostid'], record['*name'])],
                delay=record['delay'],
                http_user=record['http_user'],
                http_password=record['http_password'],
                steps=[{
                    'no': '1',
                    'name': record['name'],
                    'url': record['url'],
                    'posts': record['posts'],
                    'required': record['required'],
                    'status_codes': record['status_codes']
                }]
            )
        except ZabbixAPIException as error:
            print("Error updating web scenario '" + str(record['*name']) + "' on host", record['hostid'], '\n', error)



if __name__ == '__main__':
    # Code for enabling logging output for pyzabbix in python console:
    # stream = logging.StreamHandler(sys.stdout)
    # stream.setLevel(logging.DEBUG)
    # Code to write logs to a file in the directory where the script runs
    file = logging.FileHandler("HttpTestUpdate_" + datetime.datetime.now().strftime("%Y-%m%d-%H%M") + '.log',
                               mode='w')
    file.setLevel(logging.DEBUG)
    log = logging.getLogger('pyzabbix')
    # log.addHandler(stream)
    log.addHandler(file)
    log.setLevel(logging.DEBUG)
    default = {
        'hostid': 'Required',
        '*name': 'Required',
        'delay': '',
        'http_user': '',
        'http_password': '',
        'name': 'Required',
        'url': 'Required',
        'posts': '',
        'required': '',
        'status_codes': ''
    }
    retries = 4
    list1 = []
    httpdict = {}
    iddict = {}
    hostdict = {}
    rowcount1 = 0
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
    gethostdict(hostdict)
    gethttptestdict(httpdict)
    if readcsvfile(list1):
        rowcount1 = len(list1)
        if rowcount1 <= 1:
            print("The imported CSV file must have a header.\nDefault header:")
            print(sorted(default.keys()))
            sys.exit(2)
        else:
            # Main function block
            validatewithheader(list1)
            data2 = retrievalfill(list1)
            data3 = validateinput(data2)
            print(str(len(data3)), "records loaded. Ready to write to Zabbix Server?")
            y = 1
            while y == 1:
                ask = input("y/n:")
                if ask == 'y' or ask == 'yes' or ask == 'Y' or ask == 'Yes':
                    httpupdate(data3)
                    break
                elif ask == 'n' or ask == 'no' or ask == 'N' or ask == 'No':
                    print("Write aborted.")
                    sys.exit(3)
