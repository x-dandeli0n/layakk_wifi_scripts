#!/usr/bin/env python
#########################
## lk_wiclitatoo.py :
##
##      Wi-Fi Client Targeting Tool
##
##      A tool that monitors Wi-Fi traffic and displays information
##      about clients of interest in real time.
##
## Copyright (C) 2015 LAYAKK - www.layakk.com - @layakk
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
##
## PRERREQUISITES
##      python-scapy
##      wireshark (optional, for MAC to vendor name translation)
##
## USAGE
##      See help (-h)
#########################



### Imports

import sys
from datetime import datetime
import re
import os
import resource
import platform
import argparse
import time
import fcntl, struct, socket

# Import scapy while ignoring warnings (to avoid annoying warning msg about ipv6)
tmpout = sys.stdout; tmperr = sys.stderr
sys.stdout = open('/dev/null', 'w'); sys.stderr = open('/dev/null', 'w')
from scapy.all import *
sys.stdout = tmpout; sys.stderr = tmperr

### Global variables

verbose = ""
anonymize = ""
interface = ""
refresh_interval_seconds = None
initial_pause_seconds = ""
logtofile = ""
logdir = ""
logfilenameprefix = ""
vendors_to_be_ignored_regex = ""
essids_to_be_ignored_regex = ""
additional_essids_of_interest_regex = ""
coi_file_in = ""
coi_file_out = ""
networks_of_interest_filename = ""
oui_to_vendors_filename = ""

clients = []
vendor    = dict()
firstseen = dict()
lastseen  = dict()
reasons   = dict()
bssids    = dict()
networks_probed  = dict()
networks_active  = dict()

ouis      = dict()
essid_of_interest = dict()  #(key=bssid of interest, value=essid_of_interest)

tmplist = []
timeoflastprintout = datetime.now()
timestamp = datetime.now()
faketimestamp = datetime(1900,1,1,0,0)
fieldsformat='{0:^17} | {1:^10} | {2:^8} | {3:^5} | {4:<28} -- {5:<28} | {6:<13}'


### Classes


### Functions

def create_argumentparser():

    desc =  'lk_wiclitatoo.py (v1.0) - Wi-Fi clients targeting tool\n'
    desc += 'Copyright (c) 2015 Layakk (www.layakk.com) (@layakk)'

    parser=argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=desc)
    parser.add_argument("-v", "--verbose", action='store_true', default=False)
    parser.add_argument("-a", "--anonymize", action='store_true', default=False)
    parser.add_argument("-i", "--interface", help='Interface to listen on (must alread be up and in monitor mode', required=True)
    parser.add_argument("-r", "--refresh_interval", help='Refresh interval in seconds (default=10)', type=int, default=10)
    parser.add_argument("-p", "--initial_pause_seconds", help='If this options is not specified, upon start wiclitatoo will display its configuration and wait for the ENTER key to be pressed. If specified, wiclitatoo will pause for the given number of seconds and continue without expecting any input from the user.', default="99999")
    parser.add_argument("--nolog", help='Do not create a log file', action='store_true', default=False)
    parser.add_argument("--log_dir", help='Directory for log files (default=/var/log/lk_wiclitatoo)', default="/var/log/lk_wiclitatoo")
    parser.add_argument("--log_filename_prefix", help='Name prefix for the log file (default=lk_wiclitatoo). A timestamp and a ".$HOSTNAME" suffix will automatically be appended to it.', default="wiclitatoo")
    parser.add_argument("-m", "--vendors_to_be_ignored_regex", help='Regular expression defining client vendors to be ignored (e.g: "^IntelCor$") (default="^NO-VENDOR-WILL-BE-IGNORED$", i.e. all vendors would be considered).', default="^NO-VENDOR-WILL-BE-IGNORED$")

    parser.add_argument("-n", "--networks_of_interest_filename", help='File containing networks of interest. Each line must contain exactly one BSSID and one ESSID, separated by one white space. Both BSSID and ESSID must be indicated, but any of them may be bogus if unknown (e.g. "00:00:00:00:00:00 MYESSID"). If the file name does not end in ".$HOSTNAME", that suffix will automatically be appended to it. This option is complemented with the option "--additional_essids_of_interest_regex". If "--networks_of_interest_filename" is not specified, only "--additional_essids_of_interest_regex" will determine which ESSIDs are considered of interest. (default=none)', default="")

    parser.add_argument("-e", "--additional_essids_of_interest_regex", help='Regular expression defining additional ESSIDs to be considered of interest, on top of those indicated in the networks-of-interest file (option "-n"), if any. Examples: "^WLAN_.*$" (ESSIDs begining with "WLAN_"), "^.*$" (any ESSID). Default: If a networks-of-interest is specified with the option "-n", the default value is "^NO-ADDITIONAL_ESSIDS_OF_INTEREST$"; however, if no networks-of-interest file is specified with the option "-n", the default value is "^.*$" (any ESSID).', default="^NO-ADDITIONAL_ESSIDS_OF_INTEREST$")

    parser.add_argument("-q", "--essids_to_be_ignored_regex", help='Regular expression defining ESSIDs to be ignored (e.g: "^any$") (default="^NO-ESSID-BLACKLSIT$", i.e. no ESSID would be blacklisted). An ESSID matching essids_to_be_ignored_regex will always be ignored, no matter what.', default="^NO-ESSID-BLACKLIST$")
    parser.add_argument("--coi_file_in", help='File containing clients of interest, one mac per line. New clients will be appended to the file. If the file name does not end in ".$HOSTNAME", that suffix will automatically be appended to it. (default=none)', default="")
    parser.add_argument("--coi_file_out", help='Output file that will contain clients of interest, one mac per line. It will include old and new clients of interest. If the file name does not end in ".$HOSTNAME", that suffix will automatically be appended to it. When \"--coi_file_in\" is also specified, and the reserved file name \"idem\" is used as coi_file_out, wiclitatoo will append any new clients found of interest to the existing coi_file_in. (default=none)', default="")
    parser.add_argument("-o", "--oui_to_vendors_filename", help='File containing the mapping between OUIs and the name of their corresponding vendors. Expected format: that of the "manuf" file distributed with wireshark (e.g. "/usr/share/wireshark/manuf"). (default="/usr/share/wireshark/manuf")', default="/usr/share/wireshark/manuf")
    return parser


def process_args(args):

    global verbose
    global anonymize
    global interface
    global refresh_interval_seconds
    global initial_pause_seconds
    global logtofile
    global logdir
    global logfilenameprefix
    global vendors_to_be_ignored_regex
    global essids_to_be_ignored_regex
    global additional_essids_of_interest_regex
    global coi_file_in
    global coi_file_out
    global networks_of_interest_filename
    global oui_to_vendors_filename

    verbose = args.verbose
    anonymize = args.anonymize
    interface = args.interface
    refresh_interval_seconds = args.refresh_interval
    if (args.initial_pause_seconds == "99999"):
       initial_pause_seconds = ""
    else:
       initial_pause_seconds = int(args.initial_pause_seconds)
    logtofile = not args.nolog
    logdir = args.log_dir
    logfilenameprefix = args.log_filename_prefix
    vendors_to_be_ignored_regex = args.vendors_to_be_ignored_regex
    essids_to_be_ignored_regex = args.essids_to_be_ignored_regex
    coi_file_in  = amend_filename_if_needed(args.coi_file_in)
    if (args.coi_file_out == "idem"):
        if (coi_file_in == ""):
            print ' *** ERROR *** coi_file_out set to special file name "idem", but no coi_file_in was specified. Exiting.'
            sys.exit(-1)
        else:    
            coi_file_out = coi_file_in
    else:
        coi_file_out = amend_filename_if_needed(args.coi_file_out)
    networks_of_interest_filename = amend_filename_if_needed(args.networks_of_interest_filename)
    if (args.networks_of_interest_filename == "" and args.additional_essids_of_interest_regex == "^NO-ADDITIONAL_ESSIDS_OF_INTEREST$"):
        additional_essids_of_interest_regex = "^.*$"
    else:
        additional_essids_of_interest_regex = args.additional_essids_of_interest_regex
    oui_to_vendors_filename = args.oui_to_vendors_filename


def report_configuration():
        printandlog('--------------------------------------------------')
        printandlog("       Host: {0}. Now: {1}".format(platform.node(), timestamp.strftime('%Y-%m-%d %H:%M:%S')))
        printandlog('--------------------------------------------------')
        printandlog('            lk_wiclitatoo configuration           ')
        printandlog('--------------------------------------------------')
        printandlog('Verbose:                                {0}'.format(verbose))
        printandlog('Anonymization:                          {0}'.format(anonymize))
        printandlog('Refresh interval (seconds):             {0}'.format(refresh_interval_seconds))

        if (initial_pause_seconds != ""):
           tmptxt = initial_pause_seconds
        else:
           tmptxt = "(Wait until ENTER is pressed)"
        printandlog('Initial pause (seconds):                {0}'.format(tmptxt))

        printandlog('Interface:                              {0}'.format(interface))
        printandlog('Logging to file:                        {0}'.format(logtofile))
        if (logtofile == True):
            printandlog('Log file:                               {0}'.format(logfullpath))
        printandlog('Vendors to be ignored (regex):          "{0}"'.format(vendors_to_be_ignored_regex))
        printandlog('Additional ESSIDs of interest (regex):  "{0}"'.format(additional_essids_of_interest_regex))
        printandlog('ESSIDs to be ignored (regex):           "{0}"'.format(essids_to_be_ignored_regex))

        if (coi_file_in != ""):
           tmptxt = coi_file_in
        else:
           tmptxt = "(none)"
        printandlog('Clients-of-interest input  file:        {0}'.format(tmptxt))

        if (coi_file_out != ""):
           tmptxt = coi_file_out
        else:
           tmptxt = "(none)"
        printandlog('Clients-of-interest output file:        {0}'.format(tmptxt))

        if (networks_of_interest_filename != ""):
           tmptxt = networks_of_interest_filename
        else:
           tmptxt = "(none)"
        printandlog('Networks of interest file:              {0}'.format(tmptxt))

        printandlog('OUI to vendor names file:               {0}'.format(oui_to_vendors_filename))
        printandlog('--------------------------------------------------')
        printandlog('')


def report_networks_of_interest():
        printandlog("Networks of interest:")
        printandlog("--------------------------------------------------")
        for bssid in essid_of_interest.keys():
            printandlog("{0} {1}".format(anonymize_mac(bssid), essid_of_interest[bssid]))
        printandlog("--------------------------------------------------")
        printandlog("")


def report_clients_of_interest():
        printandlog("Clients of interest:")
        printandlog("--------------------------------------------------")
        for mac in clients:
            printandlog("{0} ({1})".format(anonymize_mac(mac), vendor[mac]))
        printandlog("--------------------------------------------------")
        printandlog("")


def printandlog(text):
    print text
    if logtofile:
        logfile.write(text)
        logfile.write("\n")


def verboseprint(text):
    if verbose:
        printandlog(text)
        sys.stdout.flush()
        logfile.flush()

def anonymize_mac(mac):
    if anonymize:
        return re.sub(':([0-9a-f]{2}:){4}', ':**:**:**:**:', mac)
    else:
        return mac

def bssids_list2str(b):
    return "[" + ", ".join( anonymize_mac(str(x)) for x in b) + "]"

def printclient(c):
    # c is a client (mac address)
    printandlog(fieldsformat.format(anonymize_mac(c), vendor[c], lastseen[c].strftime('%H:%M:%S'), reasons[c], bssids_list2str(bssids[c]), networks_active[c], networks_probed[c]))


def printheader():
    printandlog('========================================================================================================================================')
    printandlog(fieldsformat.format("CLIENT", "VENDOR", "LASTSEEN", "R", "BSSIDs", "ESSIDs", "Probed_ESSIDs"))
    printandlog('========================================================================================================================================')


def printhostandtime():
    printandlog("Host: %s. Now: %s" % (platform.node(), timestamp.strftime('%Y-%m-%d %H:%M:%S')))


def printclients(cl):
    # cl is a list of clients (mac addresses)

    printhostandtime()
    printheader()
    for c in cl:
	if (reasons[c] != "."):
	        printclient(c)
    printheader()
    printhostandtime()
    printandlog("\n")

    sys.stdout.flush()
    logfile.flush()

def amend_filename_if_needed(filename):

	if (filename == ""):
		return filename

        hostname = os.uname()[1]

        # Check file name
        regexp = '.*[.]{1}' + hostname + '$'
        if not re.match(regexp, filename):
                newfilename = filename + "." + hostname
        else:
                newfilename = filename

        return newfilename


def file_exists(filename):
        return os.path.isfile(filename)

def pause():
	if (initial_pause_seconds == ""):
		try:
			input("Press ENTER to continue...")
		except SyntaxError:
			printandlog('...done. Continuing...')
			pass
	elif (initial_pause_seconds >= 0):
		printandlog('Pausing for {0} seconds...'.format(initial_pause_seconds))
		time.sleep(initial_pause_seconds)
		printandlog('...done. Continuing...')


def load_ouis():

    if not os.path.isfile(oui_to_vendors_filename):
        printandlog(' *** WARNING *** Could not open OUI file: "{0}". Execution will continue, but vendors will not be identified.\n'.format(oui_to_vendors_filename))
        return

    with open(oui_to_vendors_filename, 'r') as f:
        tmplist = list(f.read().splitlines())
        tmplist = [ t for t in tmplist if re.match("^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\t", t.lower())]
        tmplist = [ t.split("\t",1) for t in tmplist ]
        for t in tmplist:
            oui = t[0].lower()
            manuf = (t[1].split())[0]
            ouis[oui] = manuf
            #printandlog("OUI: %s ; MANUFACTURER: %s" %(oui, manuf))
 

def load_networks_of_interest():

    if (networks_of_interest_filename == ""):
        return 0

    if not os.path.isfile(networks_of_interest_filename):
        printandlog(' *** WARNING *** Could not open networks-of-interest file: "{0}". Execution will continue, but the list of networks of interest will be empty.\n'.format(networks_of_interest_filename))
        return

    with open(networks_of_interest_filename, 'r') as f:
        tmplist = list(f.read().splitlines())
        for line in tmplist:
            tmpbssid = line.split()[0].lower()
            tmpessid = line.split()[1]
            if tmpbssid not in essid_of_interest.keys():
                essid_of_interest[tmpbssid]=tmpessid
                verboseprint('Marking BSSID "{0}", ESSID "{1}" as of interest'.format(anonymize_mac(tmpbssid), essid_of_interest[tmpbssid]))


def create_file(filename):

    if os.path.isfile(filename):
        printandlog(' *** WARNING *** Was asked to create file "{0}", but file already exists. Skipping file creation.'.format(filename))
    elif os.path.exists(filename):
        printandlog(' *** ERROR *** Was asked to create file "{0}", but a directory (or something else other than a file) seems to exist with that name. Skipping file creation and exiting.'.format(filename))
        sys.exit(-1)
    else:
        basedir = os.path.dirname(filename)
        if basedir != "" and not os.path.exists(basedir):
            os.makedirs(basedir)
        f = open(filename, 'w')
        f.close()

 
def load_clients_of_interest():

    if (coi_file_in == ""):
        return 0

    if not os.path.isfile(coi_file_in):
        printandlog(' *** ERROR *** Could not open clients-of-interest input file specified: "{0}". Exiting.\n'.format(coi_file_in))
        sys.exit(-1)

    with open(coi_file_in, 'r') as f:
        tmplist = list(f.read().splitlines())
        for mac in tmplist:
            if ((not should_client_be_ignored(mac)) and (mac not in clients)):
                verboseprint('Marking client "{0}" as of interest'.format(anonymize_mac(mac)))
                initclient(mac)
                reasons[mac]+="."  # client is of interest because it was already identified as such in the past
 
def get_vendor(mac):
    oui = mac[0:8].lower()
    if oui in ouis.keys():
        tmpvendor = ouis[oui]
    else:
        tmpvendor = "--------"
    return tmpvendor


def should_client_be_ignored(mac):
    answer = False
    if re.match(vendors_to_be_ignored_regex, get_vendor(mac)):
        verboseprint('Ignoring client {0}, because its vendor ({1}) is to be ignored.'.format(anonymize_mac(mac), get_vendor(mac)))
        answer = True
    return answer

def should_essid_be_ignored(essid):
    answer = False
    if re.match(essids_to_be_ignored_regex, essid):
        verboseprint('Ignoring SSID {0}, because it matches essids_to_be_ignored ({1}).'.format(essid, essids_to_be_ignored_regex))
        answer = True
    return answer


def initclient(mac):

    verboseprint('Adding client: {0} ({1})'.format(anonymize_mac(mac), get_vendor(mac)))

    clients.append(mac)

    vendor[mac] = get_vendor(mac)
    firstseen[mac] = timestamp
    lastseen[mac]  = timestamp
    reasons[mac] = ""
    bssids[mac] = []
    networks_active[mac] = []
    networks_probed[mac] = []

    if (coi_file_out != ""):
        with open(coi_file_out, 'a') as f:
            f.write(mac + "\n")
            verboseprint("Adding client {0} to output coi file ({1})\n".format(anonymize_mac(mac), coi_file_out))


def check_interface():

    # Check if interface is in monitor mode
    retvalue = os.system("iwconfig %s | grep \"Monitor\" > /dev/null" % interface)
    if retvalue != 0:
        print "Error: The interface (%s) is not in monitor mode. Exiting." % interface
        sys.exit(-1)

    # Check if interface is up
    tempsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ioctlresult = fcntl.ioctl(tempsocket.fileno(), 0x8913, interface + '\0'*256)
    flags, = struct.unpack('H', ioctlresult[16:18])
    if (flags & 1)  == 0:
        print "Error: The interface (%s) is down. Exiting." % interface
        sys.exit(-1)


def sniffmgmt(p):

    global timeoflastprintout
    global tmplist
    global timestamp
    global clients
    global vendor

    del tmplist[:]

    #printandlog('Memory usage: %s (kb)' %resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)

    timestamp  = datetime.now()

    # Probe request?
    if p.haslayer(Dot11) and p.haslayer(Dot11ProbeReq):
        mac  = p[Dot11].addr2
        ssid = p[Dot11Elt].info
        if ssid == "":
            ssid="any"

        # Check mac and ssid for sanity
        if not re.match("^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac.lower()):
             printandlog("INFO: Discarding probe request because of ill formatted MAC")
             return
        if not re.match("^[ -~]+$", ssid):
             printandlog("INFO: Discarding probe request because of ill formatted SSID")
             return


        verboseprint("%s : Client %s is probing for %s" %(str(timestamp), anonymize_mac(mac), ssid))

        # Client is probing for an ESSID of interest?
        if ((ssid in essid_of_interest.values() or re.match(additional_essids_of_interest_regex, ssid)) and not should_essid_be_ignored(ssid)):

            verboseprint('That is an ESSID of interest.')

            # New client?
            if mac not in clients:
                if should_client_be_ignored(mac):
                    return
                else:
                    initclient(mac)

            # First probe?
            if not re.match(".*P.*", reasons[mac]): # P = Probe
                reasons[mac]+="P"

            # New probed SSID?
            tmplist = networks_probed[mac][:]
            if ssid not in tmplist:
                tmplist.append(ssid)
                networks_probed[mac] = tmplist[:]

            # Update last-seen timestamp
            lastseen[mac]  = timestamp

        # Client is of interest anyways? (though it is probing for a not-of-interest essid)
        elif mac in clients:

            verboseprint('That is a client of interest, though probing for a not-of-interest essid.')

            # First probe?
            if not re.match(".*p.*", reasons[mac]): # p = probe for not-of-interest essid
                reasons[mac]+="p"

            # New probed SSID?
            tmplist = networks_probed[mac][:]
            if ssid not in tmplist:
                tmplist.append(">")
                tmplist.append(ssid)
                networks_probed[mac] = tmplist[:]

            # Update last-seen timestamp
            lastseen[mac]  = timestamp


    # Active client? (not probe request and to-DS and not from-DS)
    elif p.haslayer(Dot11) and (p.FCfield & 0x03 == 0x01): #to-DS and not from-DS?
        # Note: 
        #     addr1 = receiver
        #     addr2 = transmitter
        #     addr3 = either original source or intended destination
        #     addr4 = final source when frame is both tx and rx on a wireless DS
        #   In ToDS-No_FromDS:
        #     receiver    = BSSID
        #     transmitter = client
        bssid = p[Dot11].addr1
        mac   = p[Dot11].addr2

        verboseprint('{0} : Client {1} is talking to BSSID {2}'.format(str(timestamp), anonymize_mac(mac), anonymize_mac(bssid)))

        # Client is talking to AP of interest?
        if bssid in essid_of_interest.keys():

            verboseprint('That is a BSSID of interest.')

            # New active client?
            if mac not in clients:
                if should_client_be_ignored(mac):
                    return
                else:
                    initclient(mac)

            # First time it is active?
            if not re.match(".*A.*", reasons[mac]):  # A = Active with a bssid of interest
                reasons[mac]+="A"

            # New BSSID?
            tmplist = bssids[mac][:]
            if bssid not in tmplist:
                tmplist.append(bssid)
                bssids[mac] = tmplist[:]

            # New ESSID?
            tmplist = networks_active[mac][:]
            if essid_of_interest[bssid] not in tmplist:
                tmplist.append(essid_of_interest[bssid])
                networks_active[mac] = tmplist[:]

            # Update last-seen timestamp
            lastseen[mac]  = timestamp

        # Client is of interest anyways? (though talking to a not-of-interest AP)
        elif mac in clients:

            verboseprint('That is a client of interest, though talking to a not-of-interest bssid.')

            # First time it is active?
            if not re.match(".*a.*", reasons[mac]):  # a = active, though with a not-of-interest bssid
                reasons[mac]+="a"

            # New BSSID?
            tmplist = bssids[mac][:]
            if bssid not in tmplist:
                tmplist.append(">")
                tmplist.append(bssid)
                bssids[mac] = tmplist[:]



    # Print updated list of interesting clients, from time to time
    elapsedTime = timestamp - timeoflastprintout
    if ( elapsedTime.seconds >= refresh_interval_seconds ):
        timeoflastprintout = timestamp
        os.system('clear')
        sorted_clients = sorted(lastseen, key=lastseen.get, reverse=False)
        printclients(sorted_clients)
        verboseprint("\n\n")


### main

# Process arguments
aparser = create_argumentparser()
args = aparser.parse_args()
process_args(args)


#exit()

# Check interface
check_interface()

# Create logfile
if not os.path.isdir(logdir):
    os.makedirs(logdir)
logfullpath = amend_filename_if_needed(logdir + '/' + logfilenameprefix + '-' +
               datetime.now().strftime('%Y-%m-%d--%H-%M-%S') +
               '.log' + '.' + platform.node())
logfile = open(logfullpath, "w")

# Report configuration
report_configuration()

# Load known vendors
load_ouis()

# Load networks of interest
load_networks_of_interest()


# Load clients of interest (using a fake timestamp)
tmp = timestamp
timestamp = faketimestamp
load_clients_of_interest()
timestamp = tmp

# Create coi_file_out if needed
if (coi_file_out != "" and coi_file_out != coi_file_in):
	create_file(coi_file_out)

# Report networks and clients of interest
report_networks_of_interest()
report_clients_of_interest()

# Flush output
sys.stdout.flush()
logfile.flush()

# Initial pause
pause()

# Go!
sniff(iface=interface, prn=sniffmgmt, store=0)