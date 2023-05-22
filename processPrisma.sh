#!/bin/sh
##########################################################################################
##
##  processPrisma
##  Author: Chris Jenkins
##  This script takes the raw (csv) output from Prisma cloud and performs the following:
##  - Deduplicate CVEs
##  - Filters by cluster name
##  - Filters where CVE id starts with "CVE-"
##  - Get critical or high severity as scored by Prisma Cloud
##  - Checks CVE in Red Hat database and gets Severity
##  - Creates a new csv file with the additional data
##
## This script is NOT officially supported by Red Hat. 
##
##########################################################################################

lines_in_file () {
   lines=$(wc -l $1 | awk '{print $1}')
   echo " - Lines after $2 filter: $lines"
}

apply_filter () {
   in=$1
   filter=$2
   column=$3
   ext=$4
   awk -v filter=$filter -v col=$column -vFPAT='[^,]*|"[^"]*"' '$col ~ filter {print $0}' $in > ${in}_${ext}
   lines_in_file ${in}_${ext} $filter
}

if=$1
cluster=$2
basefile=${if%.*}
echo
echo "Processing infile $if for cluster $cluster"
headers=$(head -1 $if)
echo " - Lines in total: $(wc -l ${if}| awk '{print $1}')"

## De-duplicate CVEs
awk -vFPAT='[^,]*|"[^"]*"' '!_[$8]++' $if > ${basefile}_dedupe
lines_in_file ${basefile}_dedupe "de-duplicate"

## Filter by cluster
apply_filter ${basefile}_dedupe $cluster 29 "cluster"

## Filter where CVE id ="CVE-"
apply_filter ${basefile}_dedupe_cluster "CVE-" "8" "cves"

## Get critical or high severity
apply_filter ${basefile}_dedupe_cluster_cves "critical|high" "11" "crit_high"

## Add RH Severity to the headers
newHeaders="Red Hat Severity,CVE Link,$headers"

## Run through all the CVE and look for entries in the Red Hat DB
cvesFound=0
totalLines=$(wc -l ${basefile}_dedupe_cluster_cves_crit_high | awk '{print $1}')
echo "Checking $totalLines CVEs in the Red Hat CVE Database"
echo $newHeaders > ${basefile}_dedupe_cluster_cves_crit_high_rh_severity.csv 
while read line
do 
echo -n "$totalLines, "
   cve=$(echo $line | awk -vFPAT='[^,]*|"[^"]*"' '{print $8}')
   severity=$(curl -s https://access.redhat.com/hydra/rest/securitydata/cve/${cve}.json | jq '.threat_severity' 2> /dev/null | tr -d '"')
   if [ -z "$severity" ]
    then
      link="Not Found"
      severity="Not Found"
    else
      ((cvesFound=cvesFound+1))
      lcCve=$(echo $cve | tr '[A-Z]' '[a-z]')
      link="https://access.redhat.com/security/cve/$lcCve"
   fi
   echo "$severity,$link,$line" >> ${basefile}_dedupe_cluster_cves_crit_high_rh_severity
   ((totalLines=totalLines-1))
done < ${basefile}_dedupe_cluster_cves_crit_high 
sort ${basefile}_dedupe_cluster_cves_crit_high_rh_severity >> ${basefile}_dedupe_cluster_cves_crit_high_rh_severity.csv
echo
echo " - $cvesFound in the Red Hat database"
echo " Red Hat Severity Levels:"
echo
awk -vFPAT='[^,]*|"[^"]*"' '{print $1}' ${basefile}_dedupe_cluster_cves_crit_high_rh_severity | sort | uniq -c | sort
echo "Output file: ${basefile}_dedupe_cluster_cves_crit_high_rh_severity.csv"
echo


