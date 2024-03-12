'''
requires ping
requires ip utility on Linux or netsh utility on Windows.

HOW TO RUN:
python mtu_probe.py <ip or hostname>

this version is using system 'ping' utility.
PRO:
available without root/admin
available without other Python modules or ext programs [i.e. scapy requires Npcap on windows]
CONS:
different output for Linux or Windows
no reliable errorcode
windows version may be localized
Linux version

#TODO
#Jumbo Frames
#resolve problem with hostname containing "ttl" substring


'''
import platform
import subprocess
import sys
try:
    from icecream import ic
    HAVE_IC = True
except ImportError:
    HAVE_IC = False

HAVE_IC = False #uncomment for debug output

VERSION = "0.1"
encodings_to_try = ['cp866', 'utf-8', 'utf-16', 'cp1251']
ok = 'ok'
FRAGMENTATION_NEEDED= 'framentation needed'
blackhole = 'blackhole'
noroute = 'noroute'
ttlexpired = 'ttlexpired'
start_size = 1400
i_already_printed_codepage=False

def check_args():
    '''we need server name in CLI args '''
    if len(sys.argv) != 2:
        return False

def checkos():
    '''find OS version and modify ping keys for it'''
    os = platform.system()
    if os.lower() == "linux":
        tempdict = {"dfkey":"-O -M do", "pingsize":"-s",
                 "count":"-c",
                 }
    if os.lower() == "windows":
        tempdict={"dfkey":"-f", "pingsize":"-l",
                 "count":"-n",
                 }
    print(f'Operating system detected as {os}')
    return tempdict

def try_decoding_with_multiple_encodings(byte_string, encodings):
    '''to correctly show /'subprocess/' output, this function check several used encodings'''
    for encoding in encodings:
        try:
            decoded_string = byte_string.decode(encoding)
            return decoded_string, encoding
        except UnicodeDecodeError:
            pass
    return None, None

def parse_ping(pingoutput,server):
    '''get ping output strings from CLI and find info these'''
    #this version does not cover possible ping outputs:
    #   ttl expired during reassembly, no route to host, redirect
    # and probable some other

    #acutally i need only to skip first blank line (windows)
    #then skip start string
    #and the 2nd or 3rd string is the ping output
    linelist=pingoutput.splitlines()
    for line in linelist:
        #ic(line)
        if line is None or not line.strip():
            #print('empty line')
            pass
            #ic(f'empty pass {line}')
        else:
            if server in line.lower() and 'ttl' in line.lower():
                #ic(f'{server} reply successful')
                return('ok', line)
            if server in line.lower() and 'ttl' not in line.lower():
                #ic(f'starting line')
                pass
            if ('фрагментация' in line.lower() or
                'frag' in line.lower() or
                'local error: message too long' in line.lower()
                ):
                #ic(f'fragmentation needed!')
                return('framentation needed', line)
            if 'time to live'in line.lower() or 'срок жизни' in line.lower():
                #ic(f"TTL expired. I'll try to find something about MTU, ",
                #    "but it's better fix the loop first!")
                return('ttlexpired', line)
            if 'no route' in line.lower() or 'маршрут'in line.lower():
                #ic(f"TTL expired. I'll try to find something about MTU, ",
                #    "but it's better fix the loop first!")
                return('noroute', line)
            if ('unreachable' in line.lower() or
                 'недоступ' in line.lower() or
                   'no answer' in line.lower()
                   ):
                #ic(f"Fail. Possible blackhole?")
                return('blackhole', line)
            if ('100% packet loss' in line.lower()):
                #linux - empty timeout line and final result 100% fail.
                return('blackhole', line)
    return(False, "ping result not parsed")

def runsystemping(parameter_dict, server, size = 32, number = 1, display = True):
    '''
    possible return strings: ok, framentation needed, blackhole,
                                noroute, ttlexpired
    '''
    global i_already_printed_codepage
    pingstring = (
        f'ping '
        f'{parameter_dict["count"]} {number} '
        f'{parameter_dict["dfkey"]} '
        f'{parameter_dict["pingsize"]} {size} '
        f'{server}'
    )
    if display and HAVE_IC:
        ic(pingstring)
    ping_process = subprocess.Popen(pingstring,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    shell=True)
    output, _ = ping_process.communicate()

    decoded_output, chosen_encoding = try_decoding_with_multiple_encodings(output, encodings_to_try)
    #to parse windows ping output - string 3 must contain <server> if reply is OK.
    #to parse linux ping output - string 1 must contain <server> if reply is OK.

    output, line = parse_ping(decoded_output,server) #for specific size!

    if display:
        print(f'output is /{line}/ which i understood as {output}')
    mtu_from_ping = None

    if output is FRAGMENTATION_NEEDED:
        #linux frag_needed may have an mtu value
        mtu_from_ping = line.strip()[10][:-1]
        if display:
            print(mtu_from_ping)

    if i_already_printed_codepage is False:
        print(f'btw, terminal encoding seems to be {chosen_encoding}')
        i_already_printed_codepage = True
    return(output, mtu_from_ping)

def view_pmtud_cache(server):
    """view OS PMTUD cache (linux - from ip route, windows - from netsh )"""
    os = platform.system()
    if os.lower() == "linux":
        decoded_output = "no linux code yet"
        cache_string = f'ip route get to {server} | grep cache'
        if HAVE_IC:
            ic(cache_string)
        cache_process = subprocess.Popen(cache_string,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL,
                                         shell=True,
                                         universal_newlines=True)
        output, _ = cache_process.communicate()
        #ic (output, len(output), len(output.splitlines()[0].split()))
        if len(output.splitlines()[0].split()) == 5:
            output = output.split()[4]
        else:
            output = 'no cache found'
        #decoded_output, _ = try_decoding_with_multiple_encodings(output, encodings_to_try)
        #parsing nesh output - expecting string 4, last word to contain PMTUD size
        #output = decoded_output.splitlines()[4].split()[-1]
        #return(output)
    if os.lower() == "windows":
        cache_string = f'netsh interface ipv4 show destinationcache address={server}'
        if HAVE_IC:
            ic(cache_string)
        cache_process = subprocess.Popen(cache_string,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL)
        output, _ = cache_process.communicate()
        decoded_output, _ = try_decoding_with_multiple_encodings(output, encodings_to_try)
        #parsing nesh output - expecting string 4, last word to contain PMTUD size
        output = decoded_output.splitlines()[4].split()[-1]
    return output

def hostname_safety_check(server):
    '''check if hostname has "ttl" in it '''
    if 'ttl' in server.lower():
        print('WARNING! Server name contains "ttl". ',
              'Please run again using IP address of the server')

#init
print(f'MTU-probe version {VERSION}. made by Igor Perfilov.')
if check_args() is False:
    print('No servername/IP found. Please run "python mtu-probe-debug.py <servername/IP>"')
    sys.exit()
else:
    remotehost = sys.argv[1]


#preparation
os_dict = checkos()
print('Running ping with default size 32 to pave the way')
runsystemping(parameter_dict = os_dict,server = remotehost, number = 2)
print('Checking MTU size from OS cache')
pmtud_cache = view_pmtud_cache(server = remotehost)

print(f'PMTUD cache for {remotehost} is {pmtud_cache}')

#measurement
print('starting from ping size 1472 aka MTU 1500')
result, mtu_from_ping = runsystemping(parameter_dict = os_dict,
                                      server = remotehost,
                                      size=1472,
                                      number=2)
if result == ok:
    size = 1472
    print('MTU 1500 detected',
          "The result may be wrong if DF-bit is cleared somewhere",
          )

#if result == FRAGMENTATION_NEEDED:
    #Linux - take Fragment size from ping reply and compare to ip route
    #windows - just check pmtud cache from netstat

    #if mtu_from_ping:
    #    print(f'ping says MTU is {mtu_from_ping} on router ????')
    #    print('comparing to OS cache')
    #    pmtud_cache = view_pmtud_cache(server = remotehost)
    #    print(f'PMTUD cache for {remotehost} is {pmtud_cache}')
    #    start_size = mtu_from_ping
    #else:
    #pmtud_cache = view_pmtud_cache(server = remotehost)
    #print(f'PMTUD cache for {remotehost} is {pmtud_cache}')
#    pass


if result == blackhole:
    print('Possible blackhole detected')

if result == blackhole or result == FRAGMENTATION_NEEDED:
    pmtud_cache = view_pmtud_cache(server = remotehost)
    print(f'PMTUD cache for {remotehost} is {pmtud_cache}')
    size_range = range(start_size, 400, -100)
    for size in size_range:
        result, _ = runsystemping(parameter_dict = os_dict,
                                  server = remotehost,
                                  size=size,
                                  number=1)
        if result == ok:
            if HAVE_IC:
                ic(f'Found some passing MTU {size} , result={result}')
            break
        else:
            if HAVE_IC:
                ic(f'Found some passing MTU {size} , result={result}')
                print(f'Size {size} not passing, trying 100 byte less.')

    if result == ok:
        #num_pings = 1
        #os = platform.system()
        #if os.lower() == "linux":
        #    num_pings = 2   #
        print(f'MTU is at least {size}. Going up:')
        size_range_up = range(size, size+100, 1)
        print('Increasing MTU by 1 byte: ', end ='', flush=True)
        for size in size_range_up:
            result, _ = runsystemping(parameter_dict = os_dict,
                                      server = remotehost, size=size,
                                      number=1,
                                      display = False)
            print('.', end ='', flush=True) #printing dots in one line
            if result == blackhole or result == FRAGMENTATION_NEEDED:
                size=size-1 #substracting last failed step - it's above MTU actually
                break
        print()
        print(f'Found max ping size {size}, MTU {size+28} , result={result}')


#compare measured size with pmtud cache for final output
pmtud_cache = view_pmtud_cache(server = remotehost)
#print(f'RESULT:')

if pmtud_cache == 'no cache found':
    pmtud_cache = 'no cache found. PMTUD broken. Fix it or set MTU manually.'
print(f'Measured MTU to {remotehost} is {size+28} (L2 value. Substract 28 for max ping).',
      f'System PMTUD cache is: {pmtud_cache}')
