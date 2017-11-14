#!/usr/bin/env python

sipmsg = """
INVITE sip:+17326522935@67.231.13.113:5060 SIP/2.0
Via:SIP/2.0/UDP 10.0.12.30;branch=z9hG4bKBroadWorks.-mr0m9h-10.0.12.4V5060-0-486851694-278554836-1510654719336
From:<sip:+14844436457@s.phl1.bwp.coredial.com>;tag=278554836-1510654719336
To:"BVOIP COMPANY  "<sip:+17326522935@67.231.13.113>;tag=gK0870f955
Call-ID:774386754_52059909@67.231.13.113
CSeq:486851694 INVITE
Route:<sip:10.0.12.4;r2=on;lr;ftag=gK0870f955;vsf=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>,<sip:198.58.41.4;r2=on;lr;ftag=gK0870f955;vsf=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>
Contact:<sip:as.bwp.coredial.com:5060>
Allow:ACK,BYE,CANCEL,INFO,INVITE,OPTIONS,PRACK,REFER,NOTIFY,UPDATE
Supported:
Accept:application/media_control+xml,application/sdp,application/x-broadworks-call-center+xml
Max-Forwards:10
Content-Type:application/sdp
Content-Disposition:session;handling=required
Content-Length:271

v=0
o=BroadWorks 23604406 1 IN IP4 10.0.12.30
s=-
c=IN IP4 198.58.45.7
t=0 0
m=audio 37814 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=maxptime:20
a=sendrecv
a=rtcp:37815
a=pfc:4.55.21.66
a=pfm:5638
"""
headers = dict()
for line in sipmsg.split("\n"):
    l = line.split(":", 1)
    for i in range(len(l)):
        print( i, l[i] )
    if len(l) > 1 and l[0].find("=") == -1:
        headers[l[0]] = l[1]
print( headers )
