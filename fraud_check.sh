#!/bin/bash

DIR=/home/mcallist/bwlogtools
COMBINED=/var/tmp/combinedlog.txt
MESSAGE_FILE=/var/tmp/message.txt

RECIPIENT=fraud@example.com
SUBJECT="Potential Broadworks Fraud"
cat > $MESSAGE_FILE <<-EOF
Potential Unauthorized use on Broadworks

Over approximately the last 2 hours these numbers made calls to 011*
numbers more than 15 times.  The number of times per number is on the
right.

You should be able to find the number in the portal to identify the
customer and should find a way to change the peer password or shutdown
calling for this user and maybe the whole group.

EOF


rm ${COMBINED}
for log in $(${DIR}/log_fisher.py); do
    cat $log >> ${COMBINED}
done

nice ${DIR}/bwfraud.py -m "^INVITE sip:011" -d OUT -t'10.0.12.20' ${COMBINED} | awk '{if ($2 > 15) print}' > /var/tmp/frauds.txt
cat /var/tmp/frauds.txt >> ${MESSAGE_FILE}
COUNT=$(wc -l /var/tmp/frauds.txt | awk '{print $1}')
if [ $COUNT -gt 0 ]; then
    mail -s "${SUBJECT}" ${RECIPIENT} < ${MESSAGE_FILE}
fi
