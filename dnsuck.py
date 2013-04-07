# Fahad Ghani, fahadghani@cs.ucsb.edu

from optparse import OptionParser
import time
from scapy.all import *

diction = {}
time_diction = {}
to_be_deleted_from_time_diction = set()
interval = 5

def got_packet_callback(pkt):

    if(DNS in pkt):
        min_allowed_time = time.time() - interval

        to_be_deleted_from_diction = set()
        for k in time_diction:
            if (k<min_allowed_time):
                to_be_deleted_from_time_diction.add(k)
                for id in time_diction[k]:
                    to_be_deleted_from_diction.add(id)

        for id in to_be_deleted_from_diction:
            if(diction.has_key(id)):
                del(diction[id])

        for k in to_be_deleted_from_time_diction:
            if (k<min_allowed_time):
                if(time_diction.has_key(k)):
                    del(time_diction[k])

    store_detect(pkt)

def store_detect(pkt):
   if DNS in pkt:

        l=pkt.getlayer('DNS')
	ip=pkt.getlayer('IP')

        if(l.qr==0):
	    t = ('REQ', ip.src, ip.dst, l.qd.qname)
	    diction[l.id] = set([])
	    diction[l.id].add(t)

            time_now = int(time.time())
            if(time_diction.has_key(time_now)):
                time_diction[time_now].add(l.id)
            else:
                time_diction[time_now]=set()
                time_diction[time_now].add(l.id)
	else:
            count = l.ancount

            if(count==0):
                ans = "null"
            if(count==1):
                ans = l.an.rdata
            else:
                ans = ""
                x = l.an
                for i in range(0, l.ancount):
                    if (x.type==1):
                        ans = (x.rdata) + "," + ans
                    x = x.payload
                ans = ans[:len(ans)-1]

	    diction[l.id].add( ('AN', ip.src, ip.dst, l.qd.qname, ans) )

        if (len(diction[l.id])>2):
            answer = ""
            for s in diction[l.id]:
                i = 1;
                if (s[0]=='AN'):
                    answer = ' AN'+str(i)+": " + s[4]
                    i+=1
            answer = answer[1:]
	    print 'DETECT: REQ: %s NAM: %s SRC: %s:%s DST: %s:%s %s' % (str(l.id) , l.qd.qname, ip.dst, str(ip[UDP].dport), ip.src, str(ip[UDP].sport), answer)


def main():
    parser = OptionParser()
    parser.add_option("-i", dest="iface")
    parser.add_option("-t", dest="tim")

    interface = ()
    (options, args) = parser.parse_args()
    if options.iface:
        interface = options.iface

    if options.tim:
        interval = options.tim
    else:
        interval = 5

    if (interface):
        sniff(iface= interface,prn= got_packet_callback, filter="port 53")
    else:
        sniff(prn= got_packet_callback, filter="port 53")


if __name__ == "__main__":
    main()
