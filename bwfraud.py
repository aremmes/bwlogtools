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
from itertools import groupby
from datetime import datetime
import time
import struct
import socket
import getopt

VERSION=.02

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

  def siplogs(self, regex=None, dir=None, toip=None):
    toreg = "<sip:(?:\+|011)?\d+@{0}"
    siplogs = [log for log in self.logs if log.type() == 'SipXSLogEntry']
    if   regex == None and dir == None and toip == None: 
      return siplogs
    elif regex != None and dir == None and toip == None:
      return [siplog for siplog in siplogs if regex in siplog.sipmsg or re.search(regex, siplog.sipmsg)]
    elif regex == None and dir != None and toip == None:
      return [siplog for siplog in siplogs if siplog.direction == dir]
    elif regex == None and dir == None and toip != None: 
      return [siplog for siplog in siplogs if re.search(toreg.format(toip), siplog.headers['To'])]
    elif regex != None and dir == None and toip != None:
      return [siplog for siplog in siplogs if regex in siplog.sipmsg or re.search(regex, siplog.sipmsg)]
    elif regex == None and dir != None and toip != None:
      return [siplog for siplog in siplogs if siplog.direction == dir
        and re.search(toreg.format(toip), siplog.headers['To'])]
    elif regex != None and dir != None and toip == None:
      return [siplog for siplog in siplogs if (regex in siplog.sipmsg or re.search(regex, siplog.sipmsg))
        and siplog.direction == dir ]
    else:
      return [siplog for siplog in siplogs if (regex in siplog.sipmsg or re.search(regex, siplog.sipmsg))
        and siplog.direction == dir and re.search(toreg.format(toip), siplog.headers['To'])]

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

def usage():
  usage_str = """
usage: arg.py [-h] [-p FILENAME] [-m REGEX] [--bwip BWIP] XSLog

bwfraud tooly analyzes BroadWorks XS logs for call patterns
to detect possible unauthorized call usage

positional arguments:
  XSLog                 XSLog to parse

optional arguments:
  -h, --help            show this help message and exit
  -m REGEX, --match REGEX
                        Pattern to match
  -d, --dir DIR         Direction of message (IN, OUT)
  -x, --xtract WARN:CRIT
                        Extract calls exceeding thresholds
  -s, --span MINS       Time span for threshold count
"""
  print(usage_str)

def parse_argv():

  arg_dict = {}
  try:
    opts, args = getopt.getopt(sys.argv[1:], "hm:d:t:x:s:",
                 ["help","match=","dir=","toip=","xtract=","span="])
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
    elif o in ("-t", "--toip"):
      arg_dict['toip'] = a
    elif o in ("-x", "--xtract"):
      arg_dict['xtract'] = split( a, ":" )
    elif o in ("-s", "--span"):
      arg_dict['span'] = a
    else:
      assert False, "unhandled option"

  if len(args) != 1:
    print("Error: XSLog not specified!")
    usage()
    sys.exit()

  arg_dict['XSLog'] = args[0]
  return arg_dict

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
  span = datetime.timedelta(minutes=spanmins)
  for log in siplog:
    count = count_by_range( siplog, log.datetime - warn, log.datetime )
    if count >= warnthres and count < critthres:
      return ('warn', log.datetime)
    elif count >= critthres:
      return ('crit', log.datetime)
  return None

def main(argv):
  args = parse_argv()
  
  if not os.path.isfile(args['XSLog']): 
    print("ERROR:  Cannot open XSLog: %s" % args['XSLog'])
    usage()
    sys.exit()

  try:
    xslog = XSLog(str(args['XSLog']))
  except:
    print("ERROR: unable to parse XSLog: %s" % args['XSLog'])
    sys.exit()

  siplogs = xslog.siplogs(args['match'] if 'match' in args else None,
    args['dir'] if 'dir' in args else None,
    args['toip'] if 'toip' in args else None)
  bycaller = group_by_caller( siplogs )

  #for log in siplogs:
  #  print log
  for tn in bycaller:
  #  if 'dir' in args:
  #    if log.direction == args['dir']:
  #      print log
  #  else:
    print( "{0}\t{1}".format( tn, len( bycaller[tn] ) ) )

if __name__ == '__main__':
  main(sys.argv)
