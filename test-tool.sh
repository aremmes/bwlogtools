#!/bin/bash

DIR=$(pwd)
DATESTR=`date "+%Y%m%d%H%M%S"`
COMBINED=${DIR}/xslog-combined.txt
NETWORK_SERVER=10.0.12.20

# International and suspicious NANP area codes to include in the regex to match
# against the To: header along with the network server IP indicated above
NANP_CANADA="204|226|236|249|250|289|306|343|365|403|416|418|431|437|438|450|506|514|519|548|579|581|587|604|613|639|647|705|709|778|780|782|807|819|825|867|873|902|905"
NANP_CARIBN="242|246|264|268|284|345|441|473|649|664|721|758|767|784|809|829|849|868|869|876"
NANP_PACIFC="670|671|684"
NANP_POISON="218|319|605|641|712"
# All international/poison NPAs in one expression
NANP_REGEX="(?:\+?1)?(?:${NANP_CANADA}|${NANP_CARIBN}|${NANP_PACIFC}|${NANP_POISON})"
# Domestic NPAs, defined as NOT international/poison NPAs
DOMNPA_REGEX="(?:\+?1)?(?!${NANP_CANADA}|${NANP_CARIBN}|${NANP_PACIFC}|${NANP_POISON})"
# International (non-NANP) prefix
INTL_DIAL_REGEX="(?:(?:\+|011|00)[2-9])"
# Match all international (NANP and non-NANP) numbers
SIPUSER_REGEX="(?:${INTL_DIAL_REGEX}|${NANP_REGEX})"

TO_HDR_REGEX="<?sip:${SIPUSER_REGEX}\d+@${NETWORK_SERVER}"
TO_HDR_DOM_REGEX="<?sip:${DOMNPA_REGEX}\d+@${NETWORK_SERVER}"

SPAN=60 # in minutes for rate testing
WARN=10
CRIT=20

# Whitelist config file
WL_CONFIG=${DIR}/config/config.json
WL_HOURS=3 # How long to keep a TN in the auto whitelist

# Notification email settings
MESSAGE_FILE=/var/tmp/message-${DATESTR}.txt
FRAUDLIST_FILE=/var/tmp/frauds-${DATESTR}.txt

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

The time span is ${SPAN} minutes for international calls,
    and $(( SPAN * 2 )) for domestic calls.
The warning threshold is ${WARN} calls.
The critical threshold is ${CRIT} calls.

You should be able to find the number in the portal to identify the
customer and should find a way to change the peer password or shutdown
calling for this user and maybe the whole group.

Check each number individually as it may represent different customers.

EOF

#echo > ${COMBINED}
#for log in $(${DIR}/log_fisher.py); do
#    cat $log >> ${COMBINED}
#done
#
#if [ ! -e ${COMBINED} ]; then
#    # Nothing to do
#    exit
#fi

touch ${FRAUDLIST_FILE}
nice ${DIR}/bwfraud.py -m "^INVITE ${TO_HDR_REGEX}" -d OUT -s ${SPAN} \
    -x ${WARN}:${CRIT} -w ${WL_CONFIG} -H ${WL_HOURS} ${COMBINED} > ${FRAUDLIST_FILE}
nice ${DIR}/bwfraud.py -m "^INVITE ${TO_HDR_DOM_REGEX}" -d OUT -s $(( SPAN * 2 )) \
    -x ${WARN}:${CRIT} -w ${WL_CONFIG} -H ${WL_HOURS} ${COMBINED} >> ${FRAUDLIST_FILE}
COUNT=$(wc -l ${FRAUDLIST_FILE} | cut -d ' ' -f 1)
if [ $COUNT -gt 0 ]; then
    cat ${MESSAGE_FILE} ${FRAUDLIST_FILE}
fi
# Clean all the things
rm -f ${MESSAGE_FILE} ${FRAUDLIST_FILE} # ${COMBINED}
