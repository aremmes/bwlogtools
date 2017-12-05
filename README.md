bwlogtools
==========

bwxslogtool.py -- This tool parses sip messages out of the broadworks App Server's XS log

USAGE
=====

```
usage: bwfraud.py [-h] [-m REGEX] [-d DIR] [-t REGEX] [-x W:C] [-s MINS] [-w FILE] [-D DAYS] XSLog

bwfraud tool analyzes BroadWorks XS logs for call patterns
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
```

The -m flag takes a regular expression to match against the messages. Something like the following would print all SIP INVITE messages in the given file:

```
./bwxslogtool.py -m "^INVITE" XSLogFile
```
Then if you wanted to see a call with a specific call-id you would do something like the following:
```
./bwxslogtool.py -m "<YOUR_CALL_ID_HERE>" XSLogFile
```
The -d flag accepts either IN or OUT, to select only incoming or only outgoing calls from the given log file, respectively.

The -t flag accepts a regular expression to match against the To: header. This is a more specific form of the -m flag.

The -x flag changes the tool's behavior to count the frequency of log entries selected for each calling number over a time period specified via the -s flag. The accepted values consist of the warning and critical thresholds over the specified time span. When combined with the -m flag to select INVITE events, one can use this mode to report on excessive call usage.

The -w flag supplements the -x flag through the use of whitelisting. The file specified in FILE will contain a JSON object pointing to two whitelist files for the automatic and manual whitelist files (also JSON format). The automatic whitelist will populate automatically with entries reported by the -x flag and will expire after the number of days specified with the -d flag (default 14 days).
