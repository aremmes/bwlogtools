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
from itertools import groupby
from datetime import datetime
from datetime import date
from datetime import timedelta
import time
import getopt
from WhiteList import WhiteList

VERSION=.03

class XSLogEntry(object):
  _siplogfmt = re.compile(r'^(?:udp|tcp)(?:\ )'
                          +'(?:[0-9]+\ Bytes\ )' 
                          +'(?P<direction>IN|OUT)(?:\ )'
                          +'(?:to|from)(?:\ )'
                          +'(?:(?P<ipaddr>.*)(?::)(?P<port>.*)\r\n)'
                          +'(?P<sipmsg>(?:.*\r\n)+)', re.M)

  _timestampfmt = re.compile(r'(?P<year>[0-9]{4})(?:\.)'
                             +'(?P<month>[0-9]{2})(?:\.)'
                             +'(?P<day>[0-9]{2})(?:\ )'
                             +'(?P<hour>[0-9]{2})(?::)'
                             +'(?P<min>[0-9]{2})(?::)'
                             +'(?P<sec>[0-9]{2})\:'
                             +'(?P<msec>[0-9]{3})(?:\ )'
                             +'(?P<tz>[A-Z]{3})$')

  def __init__(self, datetime=None, loglevel=None, logtype=None, body=None):
    self.datetime = self.convert_timestamp(datetime)
    self.loglevel = loglevel
    self.logtype = logtype
    self.body = body

  def __repr__(self):
    line = ''
    for x in range(80):
      line += '-'
    line += '\n'
    repr_str = '\n' + line + str(self.datetime)
    repr_str += " " + self.loglevel + " " + self.logtype #+ ":" + "\n"
    #repr_str += line + "\n" + self.body
    repr_str += " " + self.direction + " " + self.ipaddr + ":" + self.port
    repr_str += "\nFrom:" + self.headers['From']
    repr_str += "\nTo:" + self.headers['To']
    repr_str += "\nVia:" + self.headers['Via']
    repr_str += "\nDiversion:" + (self.headers['Diversion'] if 'Diversion' in self.headers else 'none')

    return repr_str

  def type(self):
    return self.__class__.__name__

  def convert_timestamp(self, timestr):
    match = self._timestampfmt.match(timestr)
    if not match:
      return False
    ts = match.groupdict()
    #convert timestamp entries to int HACK
    for key in ts:
      if key != 'tz':
        ts[key] = int(ts[key])
    return datetime(ts['year'], ts['month'], ts['day'], 
                    ts['hour'], ts['min'], ts['sec'], 
                    ts['msec'] * 1000 )

  def parse_headers(self, sipmsg):
    headers = dict()
    for line in sipmsg.split("\n"):
        l = line.split(":", 1)
        if len(l) > 1 and l[0].find('=') == -1:
            headers[l[0]] = l[1]
    return headers

  @staticmethod
  def factory(rawlog):
    logline, body = rawlog
    entries = [entry.strip() for entry in logline.split('|')]
    datetime, loglevel, logtype = entries[:3]
    match = XSLogEntry._siplogfmt.match(body)
    if match: 
      return SipXSLogEntry(datetime, loglevel, logtype, body, match.groupdict())
    else: 
      return GenericXSLogEntry(datetime, loglevel, logtype, body)


class SipXSLogEntry(XSLogEntry):

  def __init__(self, datetime=None, loglevel=None, 
               logtype=None, body=None, siplog=None):
    super(SipXSLogEntry, self).__init__(datetime, loglevel, logtype, body)
    self.sipmsg = siplog['sipmsg'] + "\r\n"
    self.direction = siplog['direction']
    self.ipaddr = siplog['ipaddr']
    self.port = siplog['port']
    self.headers = self.parse_headers(siplog['sipmsg'])


class GenericXSLogEntry(XSLogEntry):

  def __init__(self, datetime=None, loglevel=None, logtype=None, body=None):
    super(GenericXSLogEntry, self).__init__(datetime, loglevel, logtype, body)

class XSLog(object):
  """
  XSLog  Parses Broadworks XSLog files into a list of logs
  """

  _logstart = re.compile(r'^[0-9]{4}\.[0-9]{2}\.[0-9]{2}')

  def __init__(self, fn):
    self.logs = self.parser(fn)

  def __iter__(self):
    for log in self.logs:
      yield log

  def __getitem__(self, key):
    return self.logs[key]

  def siplogs(self, regex=None, dir=None, to=None):
    toreg = "<sip:(?:\+|011)?\d+@{0}"
    siplogs = [log for log in self.logs if log.type() == 'SipXSLogEntry']
    if   regex == None and dir == None and to == None: 
      return siplogs
    elif regex != None and dir == None and to == None:
      return [siplog for siplog in siplogs if regex in siplog.sipmsg or re.search(regex, siplog.sipmsg)]
    elif regex == None and dir != None and to == None:
      return [siplog for siplog in siplogs if siplog.direction == dir]
    elif regex == None and dir == None and to != None: 
      return [siplog for siplog in siplogs if re.search(toreg.format(to), siplog.headers['To'])]
    elif regex != None and dir == None and to != None:
      return [siplog for siplog in siplogs if regex in siplog.sipmsg or re.search(regex, siplog.sipmsg)]
    elif regex == None and dir != None and to != None:
      return [siplog for siplog in siplogs if siplog.direction == dir
        and re.search(toreg.format(to), siplog.headers['To'])]
    elif regex != None and dir != None and to == None:
      return [siplog for siplog in siplogs if (regex in siplog.sipmsg or re.search(regex, siplog.sipmsg))
        and siplog.direction == dir ]
    else:
      return [siplog for siplog in siplogs if (regex in siplog.sipmsg or re.search(regex, siplog.sipmsg))
        and siplog.direction == dir and re.search(toreg.format(to), siplog.headers['To'])]

  def parser(self, fn):
    groups = []
    keys = []
    try:
      f = open(fn, 'r')
      tmp = f.next()
      while not self._logstart.match(tmp):
        tmp = f.next()
      keys.append(tmp)
      for key, group in groupby(f, self._logstart.match):
        if key: keys.append(list(group))
        else: groups.append(list(group))
    finally:
      f.close()
    #This assumes that the parser gets a group entry for each key,
    #this may be error prone, but so far seems to work.
    keys = ["".join(k).strip() for k in keys]
    groups = ["".join(g).strip() for g in groups]
    rawlogs =  zip(keys, groups)
    return [XSLogEntry.factory(rl) for rl in rawlogs]

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

def count_by_range( logs, start, end ):
  count = 0
  for log in logs:
    if log.datetime >= start and log.datetime <= end:
      count += 1
  return count

def test_call_thresholds( siplog, warnthres, critthres, spanmins ):
  span = timedelta(minutes=spanmins)
  events = list()
  level = None
  for log in siplog:
    count = count_by_range( siplog, log.datetime - span, log.datetime )
    if count >= warnthres and count < critthres:
      if level != 'warn':
        events.append( ('warn', log.datetime) )
      level = 'warn'
    elif count >= critthres:
      if level != 'crit':
        events.append( ('crit', log.datetime) )
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
  -d, --days DAYS       When using whitelist, number of DAYS
                        to keep an entry in the automatic
                        whitelist (default 14)
"""
  print(usage_str)

def parse_argv():
  arg_dict = {}
  try:
    opts, args = getopt.getopt(sys.argv[1:], "hm:d:t:x:s:w:D:",
      ["help","match=","dir=","to=","xtract=","span=", "whitelist=", "days="])
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
    elif o in ("-D", "--days") and re.match( "\d+", a ):
      arg_dict['days'] = int(a)
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
  today = date.today()
  comp = lambda v: datetime.strptime( v, "%Y-%m-%d" ).date() <= date.today()
  awl.cleanup( comp )
  mwl.cleanup( comp )
  mwl.save_list()
  return ( awl, mwl )

def main(argv):
  args = parse_argv()
  awl = None
  mwl = None
  
  if not os.path.isfile(args['XSLog']): 
    print("ERROR:  Cannot open XSLog: %s" % args['XSLog'])
    usage()
    sys.exit()

  if 'whitelist' in args:
    ( awl, mwl ) = init_whitelists( args['whitelist'] )

  try:
    xslog = XSLog(str(args['XSLog']))
  except:
    print("ERROR: unable to parse XSLog: %s" % args['XSLog'])
    sys.exit()

  siplogs = xslog.siplogs(args['match'] if 'match' in args else None,
    args['dir'] if 'dir' in args else None,
    args['to'] if 'to' in args else None)
  bycaller = group_by_caller( siplogs )

  if 'xtract' in args:
    if 'span' not in args:
      print( "Error: span must be provided if requesting extract" )
      usage()
      sys.exit()
    ( warnthres, critthres ) = args['xtract']
    spanmins = args['span']
    tempwl = list()
    fortnight = date.today() + timedelta( days = 14 if not 'days' in args else args['days'] )
    for tn in bycaller:
      for ( level, evttime ) in test_call_thresholds( bycaller[tn], warnthres, critthres, spanmins ):
        if 'whitelist' in args:
          if not awl.exists( tn ) and not mwl.exists( tn ):
            print( "{0}\t{1}\t{2}".format( tn, level, evttime ) )
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
