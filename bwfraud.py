#!/usr/bin/env python

#----------------------------------------------------------------------------
#THE BEER-WARE LICENSE (Revision 42):
#<tdflowers@gmail.com> wrote this file. As long as you retain this notice you
#can do whatever you want with this stuff. If we meet some day, and you think
#this stuff is worth it, you can buy me a beer in return -- Tim Flowers
#----------------------------------------------------------------------------


import os.path
import re
import sys
import json
from datetime import date, datetime, timedelta
import time
import getopt
from XSLog import XSLogEntry, GenericXSLogEntry, SipXSLogEntry, XSLog
from WhiteList import WhiteList

VERSION=.04

def group_by_caller(siplogs):
  bycaller = dict()
  regex = "<sip:(?:011|\+)?(\d+)@.*"
  for log in siplogs:
    m = re.search( regex, log.headers['Diversion'] if 'Diversion' in log.headers else log.headers['From'] )
    if m != None:
      tn = m.group( 1 )
      if tn not in bycaller:
        bycaller[tn] = list()
      bycaller[tn].append( log )
  return bycaller

def test_call_thresholds( siplog, warnthres, critthres, spanmins ):
  span = timedelta(minutes=spanmins)
  events = list()
  level = None
  for log in siplog:
    filtfunc = lambda x: x.datetime >= log.datetime - span and x.datetime <= log.datetime
    count = len( filter( filtfunc, siplog ) )
    if count >= warnthres and count < critthres:
      if level != 'warn':
        events.append( ('warn', log.datetime, count) )
      level = 'warn'
    elif count >= critthres:
      if level != 'crit':
        events.append( ('crit', log.datetime, count) )
      level = 'crit'
    else:
      level = None
  return events

def usage():
  usage_str = """
usage: bwfraud.py [-h] [-m REGEX] [-d DIR] [-t REGEX] [-x W:C] [-s MINS] [-w FILE] [-D DAYS] XSLog

bwfraud tooly analyzes BroadWorks XS logs for call patterns
to detect possible unauthorized call usage

positional arguments:
  XSLog                 XSLog to parse

optional arguments:
  -h, --help            show this help message and exit
  -m REGEX, --match REGEX
                        Pattern to match
  -d, --dir DIR         Direction of message (IN, OUT)
  -t, --to REGEX        Pattern to match To: header
  -x, --xtract WARN:CRIT
                        Extract calls exceeding thresholds
  -s, --span MINS       Time span for threshold count
  -w, --whitelist FILE  Use a whitelist configured in FILE
  -H, --hours HOURS     When using whitelist, number of HOURS
                        to keep an entry in the automatic
                        whitelist (default 3)
"""
  print(usage_str)

def parse_argv():
  arg_dict = {}
  try:
    opts, args = getopt.getopt(sys.argv[1:], "hm:d:t:x:s:w:H:",
      ["help","match=","dir=","to=","xtract=","span=", "whitelist=", "hours="])
  except getopt.GetoptError:
    print("Error parsing command line options:")
    usage()
    sys.exit()

  for o, a in opts:
    if o in ("-h","--help"):
      usage()
      sys.exit()
    elif o in ("-m", "--match"):
      arg_dict['match'] = a
    elif o in ("-d", "--dir") and a in ('IN','OUT'):
      arg_dict['dir'] = a
    elif o in ("-t", "--to"):
      arg_dict['to'] = a
    elif o in ("-x", "--xtract") and re.match( "\d+:\d+", a ):
      arg_dict['xtract'] = map( int, a.split( ":" ) )
    elif o in ("-s", "--span") and re.match( "\d+", a ):
      arg_dict['span'] = int(a)
    elif o in ("-w", "--whitelist"):
      arg_dict['whitelist'] = a
    elif o in ("-H", "--hours") and re.match( "\d+", a ):
      arg_dict['hours'] = int(a)
    else:
      assert False, "unhandled option"

  if len(args) != 1:
    print("Error: XSLog not specified!")
    usage()
    sys.exit()

  arg_dict['XSLog'] = args[0]
  return arg_dict

def init_whitelists( wl_config ):
  try:
    cfile = open( wl_config, 'r' )
    config = json.load( cfile )
    cfile.close()
  except IOError:
    sys.exit( "Cannot open configuration file: {0}".format( wl_config ) )

  awl = WhiteList( config['awl_path'] )
  mwl = WhiteList( config['mwl_path'] )
  ovr = WhiteList( config['ovr_path'] )
  today = datetime.today()
  comp = lambda v: datetime.strptime( v, "%Y-%m-%dT%H:%M:%S.%f" ) <= datetime.today()
  awl.cleanup( comp )
  mwl.cleanup( comp )
  mwl.save_list()
  return ( awl, mwl, ovr )

def main(argv):
  args = parse_argv()
  awl = None
  mwl = None
  ovr = None
  
  if not os.path.isfile(args['XSLog']): 
    print("ERROR:  Cannot open XSLog: %s" % args['XSLog'])
    usage()
    sys.exit()

  if 'whitelist' in args:
    ( awl, mwl, ovr ) = init_whitelists( args['whitelist'] )

  try:
    xslog = XSLog(str(args['XSLog']))
  except:
    print("ERROR: unable to parse XSLog: %s" % args['XSLog'])
    sys.exit()

  filter_siplogs = lambda x: ( re.search( args['match'], x.sipmsg ) if 'match' in args else True ) \
    and ( x.direction == args['dir'] if 'dir' in args else True ) \
    and ( re.search( args['to'], x.headers['To'] ) if 'to' in args else True )

  siplogs = xslog.siplogs( filter_siplogs )
  bycaller = group_by_caller( siplogs )

  if 'xtract' in args:
    if 'span' not in args:
      print( "Error: span must be provided if requesting extract" )
      usage()
      sys.exit()
    ( warnthres, critthres ) = args['xtract']
    spanmins = args['span']
    tempwl = list()
    fortnight = datetime.today() + timedelta( hours = 3 if not 'hours' in args else args['hours'] )
    for tn in bycaller:
      ( wt, ct ) = ( warnthres, critthres ) if ovr == None or not ovr.exists( tn ) else tuple(map(int, ovr.get(tn).split(":")))
      for ( level, evttime, count ) in test_call_thresholds( bycaller[tn], wt, ct, spanmins ):
        if 'whitelist' in args:
          if not awl.exists( tn ) and not mwl.exists( tn ):
            print( "{0}\t{1}\t{2}\t{3}".format( tn, level, evttime, count ) )
            tempwl.append( tn )
        else:
          print( "{0}\t{1}\t{2}".format( tn, level, evttime ) )
    if len( tempwl ) > 0:
      for tn in tempwl:
        if not awl.exists( tn ):
          awl.set( tn, fortnight.isoformat() )
      awl.save_list()
  else:
    for tn in bycaller:
      print( "{0}\t{1}".format( tn, len( bycaller[tn] ) ) )

if __name__ == '__main__':
  main(sys.argv)
