#!/bin/sh
#date 20240423

log_file="/var/log/banip.log"

while true
do
	#get iptables block list
	last_ips=`nft list chain inet fw4 input_wan |awk '/banip/ {print $3}'|uniq`

	#get Attack ip
	for ip in $(logread | awk '/authpriv.warn dropbear/ {getline; match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/); if (RSTART) print substr($0, RSTART, RLENGTH)}' | grep -v '^$' | sort | uniq -c | awk '$1 >= 5 {print $2}');
	do 
		if [[ ! "$last_ips" =~ "$ip" ]]; then
			#writing ban list to nftables
			nft insert rule inet fw4 input_wan  ip saddr $ip  counter packets 0 bytes 0 drop  comment "banip"
			echo "$(date +"[%Y-%m-%d %H:%M:%S]") banned connection from $ip." >> "$log_file"
			logger -t banip -s "$(date +"[%Y-%m-%d %H:%M:%S]") Banned connection from $ip."
		fi
	done
	sleep 10s
done
