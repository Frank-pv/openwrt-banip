#!/bin/sh
#date 20230601

log_file="/var/log/banip.log"

while true
do
	#get iptables banned list
	last_ips=`iptables -L input_wan_rule -v -n |awk '/DROP/{print $8}'|uniq`

	#get Attack ip
	for ip in $(logread | grep -A1 'authpriv.warn' | awk '{match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/); print substr($0, RSTART, RLENGTH)}' |grep -v '^$'|sort | awk '{if ($1 == ip) count++; else {ip=$1; count=1}; if (count>=5) print ip}' |uniq);
	do 
		if [[ ! "$last_ips" =~ "$ip" ]]; then
			#add ban list to iptables
			iptables -A input_wan_rule  -s $ip -j DROP
			echo "$(date +"[%Y-%m-%d %H:%M:%S]") Banned connection from $ip." >> "$log_file"
			logger -t blockip -s "$(date +"[%Y-%m-%d %H:%M:%S]") Banned connection from $ip."
		fi
	done

	sleep 10s
done
