#!/usr/bin/env python

import datetime
import glob
import re
import os.path

log_directory = "/var/broadworks/logs/appserver"
log_prefix = "XSLog"
all_log_pattern = log_directory + "/" + log_prefix + "*.txt"

log_hour_delta = 2

# Takes a datetime and returns the path to the logs that are
# approximately log_hour_delta before log_interesting_time
def interesting_logs_list(log_end_time):
    all_logs = glob.glob(all_log_pattern)
    return sorted([log for log in all_logs if log_time_filter(log, log_end_time)])

def time_range(end_time):
    return (end_time - datetime.timedelta(hours=log_hour_delta),end_time)

def datetime_from_log_filename(logfile):
    logname = os.path.basename(logfile)
    match = re.match('XSLog(\d+\.\d+\.\d+-\d+\.\d+\.\d+)\.txt', logname)
    if (match):
        return datetime.datetime.strptime(match.group(1),"%Y.%m.%d-%H.%M.%S")
    else:
        return datetime.datetime.min

def log_time_filter(log, log_end_time):
    (begin_time,end_time) = time_range(log_end_time)
    log_time = datetime_from_log_filename(log)
    return begin_time <= log_time and log_time <= end_time

def prn( x ):
    print( x )

log_interesting_time = datetime.datetime.now()
#log_interesting_time = datetime.datetime(2017,11,14,05)
map( prn, interesting_logs_list(log_interesting_time) )
