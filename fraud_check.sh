#!/bin/bash

DIR=/home/mcallist/bwlogtools
COMBINED=/var/tmp/combined.txt
NETWORK_SERVER=10.0.12.20

SPAN=60 # in minutes for rate testing
WARN=10
CRIT=20

MESSAGE_FILE=/var/tmp/message.txt

RECIPIENT=fraud@example.com
CC=noc-notify@example.com

SUBJECT="Potential Broadworks Fraud"
cat > $MESSAGE_FILE <<-EOF
Potential Unauthorized use on Broadworks

This system samples approximately 2 hours of logs from the Application
Server and then searches for times when International calls for a
single caller exceeded a warning or critical threshold over a time
span. It will report the number and the timestamp of the call that
first exceeded the warn or crit threshold for that time range.

The time span is ${SPAN} minutes.
The warning threshold is ${WARN} calls.
The critical threshold is ${CRIT} calls.

You should be able to find the number in the portal to identify the
customer and should find a way to change the peer password or shutdown
calling for this user and maybe the whole group.

Check each number individually as it may represent different customers.

EOF


rm -f ${COMBINED}
for log in $(${DIR}/log_fisher.py); do
    cat $log >> ${COMBINED}
done

if [ ! -e ${COMBINED} ]; then
    exit
fi

rm -f /var/tmp/frauds.txt
nice ${DIR}/bwfraud.py -m "^INVITE sip:011" -d OUT -t"${NETWORK_SERVER}" -s ${SPAN} -x ${WARN}:${CRIT} ${COMBINED} > /var/tmp/frauds.txt
cat /var/tmp/frauds.txt >> ${MESSAGE_FILE}
COUNT=$(wc -l /var/tmp/frauds.txt | awk '{print $1}')
if [ $COUNT -gt 0 ]; then
    mail -s "${SUBJECT}" -c ${CC} ${RECIPIENT} < ${MESSAGE_FILE}
fi
