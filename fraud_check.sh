#!/bin/bash

DIR=/home/mcallist/bwlogtools
COMBINED=/var/tmp/combined.txt
NETWORK_SERVER=10.0.12.20

# International and suspicious NANP area codes to include in the regex to match
# against the To: header along with the network server IP indicated above
NANP_CANADA="204|226|236|249|250|289|306|343|365|403|416|418|431|437|438|450|506|514|519|579|581|587|604|613|639|647|705|709|778|780|782|807|819|867|873|902|905"
NANP_CARIBN="264|268|242|246|441|284|345|767|809|829|849|473|876|664|869|758|784|721|868|649"
NANP_PACIFC="670|671|684"
NANP_POISON="319|605|641|712|218"
NANP_REGEX="(?:\+?1)?(?:${NANP_CANADA}|${NANP_CARIBN}|${NANP_PACIFC}|${NANP_POISON})"
INTL_DIAL_REGEX="(?:(?:\+|011|00)[2-9])"
SIPUSER_REGEX="(?:${INTL_DIAL_REGEX}|${NANP_REGEX})"

TO_HDR_REGEX="<sip:${SIPUSER_REGEX}@${NETWORK_SERVER}"

SPAN=60 # in minutes for rate testing
WARN=10
CRIT=20

# Whitelist config file
WL_CONFIG=${DIR}/config/config.json
WL_DAYS=14 # How long to keep a TN in the auto whitelist

# Notification email settings
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
nice ${DIR}/bwfraud.py -m "^INVITE sip:" -d OUT -t"${TO_HDR_REGEX}" -s ${SPAN} \
    -x ${WARN}:${CRIT} -w ${WL_CONFIG} -D ${WL_DAYS} ${COMBINED} > /var/tmp/frauds.txt
cat /var/tmp/frauds.txt >> ${MESSAGE_FILE}
COUNT=$(wc -l /var/tmp/frauds.txt | awk '{print $1}')
if [ $COUNT -gt 0 ]; then
    mail -s "${SUBJECT}" -c ${CC} ${RECIPIENT} < ${MESSAGE_FILE}
fi
