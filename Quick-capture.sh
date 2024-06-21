#!/usr/bin/env bash
#!/bin/bash

echo "Linux安全检查与应急响应工具"
echo "Version: 2.0"
echo "Author: Ashro"
echo "Date: 2024-6-21"

# 检查是否存在 ifconfig 命令，如果不存在则尝试使用 ip addr 命令
if command -v ifconfig &>/dev/null; then
    ip_command="ifconfig -a"
elif command -v ip &>/dev/null; then
    ip_command="ip addr"
else
    echo "无法找到合适的命令来获取 IP 地址，请手动检查。"
    exit 1
fi

date=$(date +%Y%m%d-%H%M%S)
ipadd=$($ip_command | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d '/' -f 1)

check_dir="/tmp/${date}/"
log_dir="/tmp/${date}/"

# 删除目录及文件，使用引号防止意外的空格或特殊字符

mkdir -p "/tmp/${date}/" # 使用 -p 选项以确保路径中的所有父目录都存在
mkdir -p "$check_dir" "$log_dir" 
cd "$check_dir"

if [ "$(id -u)" != "0" ]; then
    echo "安全检查必须使用 root 账号，否则某些项无法检查。"
    exit 1
fi

saveresult="tee -a ${log_dir}checkresult.txt"
echo -e "\n************ 1.系统范围 ************\n" | $saveresult
echo "正在检查 IP 地址....." | $saveresult
echo "------------- IP 及版本 -------------"
echo "------------ IP 地址 -------------"
echo "正在检查 IP 地址....." | $saveresult
if [ -n "$ipadd" ]; then
    (echo "[*] 本机 IP 地址信息:" && echo "$ipadd") | $saveresult
else
    echo "[!!!] 本机未配置 IP 地址" | $saveresult
fi
printf "\n" | $saveresult

echo -e "************ 2.用户信息 ************\n"
echo "------------ 查看登录用户 ------------" | $saveresult
echo "正在检查正在登录的用户....." | $saveresult

echo "[*] 系统登录用户:" | $saveresult
who | $saveresult
printf "\n" | $saveresult

echo "------------ 查看用户信息 ------------" | $saveresult
echo "正在查看用户信息....." | $saveresult

echo "[*] 用户名:口令:用户标识号:组标识号:注释性描述:主目录:登录 Shell" | $saveresult
cat /etc/passwd | $saveresult
printf "\n" | $saveresult

echo "------------ 检查超级用户 --------------" | $saveresult
echo "正在检查是否存在超级用户....." | $saveresult

Superuser=$(awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd)
if [ -n "$Superuser" ]; then
    echo "[!!!] 除 root 外发现超级用户:" | $saveresult
else
    echo "[*] 未发现超级用户" | $saveresult
fi
printf "\n" | $saveresult

echo "------------ 空口令账户检测 --------------" | $saveresult
echo "正在检查空口令账户....." | $saveresult

empty_password_accounts=$(awk -F: '($2 == "") {print $1}' /etc/shadow)

if [ -n "$empty_password_accounts" ]; then
    echo "[!!!] 发现空口令账户:" | $saveresult
    echo "$empty_password_accounts" | $saveresult
else
    echo "[*] 未发现空口令账户" | $saveresult
fi
printf "\n" | $saveresult

echo "------------ 新增用户检查 --------------" | $saveresult
echo "正在检查新增用户....." | $saveresult

new_users=$(awk -F: '$3 >= 1000 && $3 != 65534' /etc/passwd)
if [ -n "$new_users" ]; then
    echo "[!!!] 发现以下新增用户:" | $saveresult
    echo "$new_users" | $saveresult
else
    echo "[*] 未发现新增用户" | $saveresult
fi
printf "\n" | $saveresult

echo "------------ 新增用户组检查 --------------" | $saveresult
echo "正在检查新增用户组....." | $saveresult

new_groups=$(awk -F: '$3 >= 1000' /etc/group)
if [ -n "$new_groups" ]; then
    echo "[!!!] 发现以下新增用户组:" | $saveresult
    echo "$new_groups" | $saveresult
else
    echo "[*] 未发现新增用户组" | $saveresult
fi
printf "\n" | $saveresult

# 检测sudoers文件中用户权限
echo "------------ 检查sudoers文件中用户权限 --------------" | $saveresult
echo "正在检查sudoers文件中用户权限....." | $saveresult

# 使用 visudo 命令查找具有 NOPASSWD 权限的用户
sudoers_users=$(visudo -c 2>&1 | grep -E '^[^#]*[[:space:]]ALL=.*NOPASSWD' | awk '{print $1}')

if [ -n "$sudoers_users" ]; then
    echo "[!!!] 发现具有 NOPASSWD 权限的用户:" | $saveresult
    echo "$sudoers_users" | $saveresult
else
    echo "[*] 未发现具有 NOPASSWD 权限的用户" | $saveresult
fi
printf "\n" | $saveresult

# 检查各账户下登录公钥
echo "------------ 检查各账户下登录公钥 --------------" | $saveresult
echo "正在检查各账户下登录公钥....." | $saveresult

# 获取所有用户目录路径
home_dirs=$(getent passwd | cut -d: -f6)

# 遍历所有用户目录
for dir in $home_dirs; do
    authorized_keys_file="$dir/.ssh/authorized_keys"
    if [ -f "$authorized_keys_file" ]; then
        echo "[!!!] 在用户 $dir 下发现登录公钥：" | $saveresult
        cat "$authorized_keys_file" | $saveresult
    fi
done

printf "\n" | $saveresult

# 检测端口进程信息
#!/bin/bash

# 输出标题
echo "3.端口进程信息"
echo "------------网络连接---------------------" | $saveresult

# 病毒木马端口检测
echo "------------病毒木马端口检测------------------" | $saveresult
echo "正在检测系统中的网络连接和监听端口....." | $saveresult

# 检查正在监听的端口
listening_ports=$(netstat -tuln | awk 'NR > 2 {print $4}' | awk -F':' '{print $NF}' | sort -nu)
if [ -n "$listening_ports" ]; then
    echo "[] 系统中正在监听的端口如下：" | $saveresult
    echo "$listening_ports" | $saveresult

    # 输出每个监听端口的详细信息
    echo "------------详细的端口信息------------------" | $saveresult
    for port in $listening_ports; do
        echo "端口: $port" | $saveresult
        # 使用 lsof 列出详细信息
        lsof -i :$port | awk 'NR==1 || /LISTEN/' | $saveresult
        echo "----------------------------------------" | $saveresult
    done
else
    echo "[] 系统中未发现正在监听的端口" | $saveresult
fi


# 检查建立的网络连接
established_connections=$(netstat -tun | grep ESTABLISHED)
if [ -n "$established_connections" ]; then
    echo "[!!!] 系统中存在建立的网络连接：" | $saverult
    echo "$established_connections" | $saverult

    # 分析建立的网络连接，查看是否有可疑连接
    suspicious_connections=$(echo "$established_connections" | awk '{print $5}' | grep -E '0.0.0.0:|127.0.0.1:' | sort -u)
    if [ -n "$suspicious_connections" ]; then
        echo "[!!!] 发现可疑的网络连接：" | $saverult
        echo "$suspicious_connections" | $saverult
    fi
else
    echo "[*] 系统中未发现建立的网络连接" | $saverult
fi

printf "\n" | $saverult

# 进程分析
echo "------------进程分析---------------------" | $saverult

# 系统进程
echo "------------系统进程------------------" | $saverult
echo "正在检查系统进程....." | $saverult
ps_output=$(ps aux)
if [ -n "$ps_output" ]; then
    echo "[*] 系统进程如下:" | $saverult
    echo "$ps_output" | $saverult
else
    echo "[*] 未发现系统进程" | $saverult
fi
printf "\n" | $saverult

# 守护进程
echo "------------守护进程------------------" | $saverult
echo "正在检查守护进程....." | $saverult
if [ -d "/etc/init.d" ]; then
    echo "[*] 系统守护进程:" | $saverult
    ls -l /etc/init.d | grep "^-" | awk '{print $9}' | $saverult
else
    echo "[*] 未发现守护进程" | $saverult
fi
printf "\n" | $saverult

# CPU和内存使用异常进程排查
echo "------------CPU和内存使用异常进程排查------------------" | $saverult

# 查找CPU使用率最高的进程
cpu_high_processes=$(ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%cpu | head -n 5)
if [ -n "$cpu_high_processes" ]; then
    echo "[!!!] CPU使用率最高的进程：" | $saverult
    echo "$cpu_high_processes" | $saverult
else
    echo "[*] 未发现CPU使用率异常的进程" | $saverult
fi

# 查找内存使用率最高的进程
memory_high_processes=$(ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%mem | head -n 5)
if [ -n "$memory_high_processes" ]; then
    echo "[!!!] 内存使用率最高的进程：" | $saverult
    echo "$memory_high_processes" | $saverult
else
    echo "[*] 未发现内存使用率异常的进程" | $saverult
fi

printf "\n" | $saverult

# 隐藏进程和反弹shell类进程扫描
echo "------------隐藏进程和反弹shell类进程扫描------------------" | $saverult

# 检查隐藏进程
hidden_processes=$(ps aux | awk '{if($8 == "S" || $8 == "D") print $0}')
if [ -n "$hidden_processes" ]; then
    echo "[!!!] 发现隐藏进程：" | $saverult
    echo "$hidden_processes" | $saverult
else
    echo "[*] 未发现隐藏进程" | $saverult
fi

# 检查反弹shell类进程
# 查询所有监听端口的网络连接
shell_processes=$(netstat -tuln | grep -E "nc -l -p|netcat|ncat|socat|shell|bind|reverse|listen|connect|exec|sh|bash|zsh|ksh|telnet|ssh|rsh|rcp|sshpass|pexpect|paramiko|plink|pscp|putty|ssh-keygen|ssh-agent|tsh|rbash|dash|mkfifo|expect|bash -c|python -c|perl -e|curl|wget|php -r|lua -e|bash -i|php -a|python -m|perl -M|ruby -e|perl -n|python -p|ruby -n|bash -s|php -l|wget -O|curl -o")
if [ -n "$shell_processes" ]; then
    echo "[!!!] 发现反弹shell类进程：" | $saverult
    echo "$shell_processes" | $saverult
else
    echo "[*] 未发现反弹shell类进程" | $saverult
fi

printf "\n" | $saverult



echo "------------运行服务----------------------" | $saveresult
echo "正在检查运行服务....." | $saveresult
if command -v systemctl &>/dev/null; then
    if systemctl list-units --type=service --state=running &>/dev/null; then
        echo "[*]以下服务正在运行：" | $saveresult
        systemctl list-units --type=service --state=running | awk '{print $1}' | $saveresult
    else
        echo "未发现正在运行的服务！" | $saveresult
    fi
else
    echo "[!!!]Systemd 未安装，无法检查正在运行的服务。" | $saveresult
fi
printf "\n" | $saveresult


echo "------------历史命令分析-------------------" | $saveresult
echo "------------历史命令分析-------------------" | $saveresult
echo "------------历史命令分析-------------------" | $saveresult
echo "正在检查操作系统历史命令....." | $saveresult

history_file="/root/.bash_history"
if [ -s "$history_file" ]; then
    echo "[*]操作系统历史命令如下:" | $saveresult
    cat "$history_file" | $saveresult
else
    echo "[!!!]未发现历史命令,请检查是否记录及已被清除" | $saveresult
fi

printf "\n" | $saveresult

echo "------------历史命令分析-------------------" | $saveresult
echo "------------历史命令分析-------------------" | $saveresult
echo "------------历史命令分析-------------------" | $saveresult


echo "------------系统定时任务分析-------------------" | $saveresult
echo "------------查看系统定时任务-------------------" | $saveresult
echo "正在分析系统定时任务....." | $saveresult
syscrontab=$(grep -v "# run-parts" /etc/crontab 2>/dev/null | grep run-parts)
if [ -n "$syscrontab" ]; then
    (echo "[!!!]发现存在系统定时任务:" && cat /etc/crontab ) | $saveresult
else
    echo "[*]未发现系统定时任务" | $saveresult
fi
printf "\n" | $saveresult

echo "------------分析系统可疑定时任务-------------------" | $saveresult
echo "正在分析系统可疑任务....." | $saveresult


# 分析可疑定时任务
dangersyscron=$(egrep "(chmod|useradd|groupadd|chattr|wget|curl|su|sudo|rsync).*\.(sh|pl|py|bash|ksh|csh|zsh)$" /etc/cron*/* /var/spool/cron/* 2>/dev/null)

if [ -n "$dangersyscron" ]; then
    echo "[!!!]发现下面的定时任务可疑，请注意！！！" | $saveresult
    echo "$dangersyscron" | $saveresult
else
    echo "[*]未发现可疑系统定时任务" | $saveresult
fi

printf "\n" | $saverult


echo "------------分析用户定时任务-------------------" | $saveresult
echo "------------查看用户定时任务-------------------" | $saveresult
echo "正在查看用户定时任务....." | $saveresult

# 检查是否存在 /var/spool/cron 目录
if [ -d "/var/spool/cron" ]; then
    # 使用 ls 命令列出所有用户的定时任务
    for user_crontab in /var/spool/cron/*; do
        username=$(basename "$user_crontab")
        crontab_content=$(cat "$user_crontab" 2>/dev/null)
        if [ -n "$crontab_content" ]; then
            (echo "[!!!]用户 $username 的定时任务如下:" && echo "$crontab_content") | $saveresult
        fi
    done
else
    echo "[!!!]未找到 /var/spool/cron 目录，无法查找用户定时任务" | $saveresult
fi

printf "\n" | $saveresult


echo "------------查看可疑用户定时任务-------------------" | $saveresult
echo "正在分析可疑用户定时任务....." | $saverult
danger_crontab=$(crontab -l 2>/dev/null | egrep "((chmod|useradd|groupadd|chattr|wget|curl|su|sudo|rsync).*\.(sh|pl|py|bash|ksh|csh|zsh)))")
if [ -n "$danger_crontab" ]; then
    (echo "[!!!]发现可疑定时任务,请注意！！！" && echo "$danger_crontab") | $saveresult
else
    echo "[*]未发现可疑定时任务" | $saverult
fi
printf "\n" | $saverult


echo "------------CPU分析-----------------" | $saveresult
echo "------------CPU情况-----------------" | $saveresult
echo "正在检查CPU相关信息....." | $saveresult
(echo "CPU使用情况如下:" && ps -aux --sort=-%cpu | awk 'NR<=5 {print $1,$2,$3,$NF}') | $saveresult
printf "\n" | $saveresult
echo "------------占用CPU前5进程-----------------" | $saveresult
echo "正在检查占用CPU前5资源的进程....." | $saveresult
(echo "占用CPU资源前5进程：" && ps -aux --sort=-%cpu | head -6 | tail -n +2)  | $saveresult
printf "\n" | $saveresult
echo "------------占用CPU较大进程-----------------" | $saveresult
echo "正在检查占用CPU较大的进程....." | $saveresult
pscpu=$(ps -aux --sort=-%cpu | awk '{if($3>=20) print $0}' | tail -n +2)
if [ -n "$pscpu" ];then
    echo "[!!!]以下进程占用的CPU超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD" 
    echo "$pscpu" | tee -a 20.2.3_pscpu.txt | $saveresult
else
    echo "[*]未发现进程占用资源超过20%" | $saveresult
fi
printf "\n" | $saverult



echo "------------secure 日志分析-------------------" | $saveresult
echo "------------成功登录-------------------" | $saveresult
echo "正在检查日志中成功登录的情况....." | $saveresult
loginsuccess=$(grep "Accepted password" /var/log/secure* 2>/dev/null | awk '{print $1,$2,$3,$9,$11}')
if [ -n "$loginsuccess" ]; then
    echo "[*]日志中分析到以下用户成功登录:"  | $saveresult
    echo "$loginsuccess" | $saveresult
    echo "[*]登录成功的IP及次数如下：" | $saveresult
    grep "Accepted " /var/log/secure* | awk '{print $11}' | sort | uniq -c
    echo "[*]登录成功的用户及次数如下:"  | $saveresult
    grep "Accepted" /var/log/secure* | awk '{print $9}' | sort | uniq -c
else
    echo "[*]日志中未发现成功登录的情况" | $saveresult
fi
printf "\n" | $saveresult

echo "------------登录失败-------------------" | $saveresult
echo "正在检查日志中登录失败的情况....." | $saveresult
loginfailed=$(grep "Failed password" /var/log/secure* 2>/dev/null | awk '{print $1,$2,$3,$9,$11}')
if [ -n "$loginfailed" ]; then
    echo "[!!!]日志中发现以下登录失败的情况:"  | $saveresult
    echo "$loginfailed"  | $saveresult
    echo "[!!!]登录失败的IP及次数如下:"  | $saveresult
    grep "Failed password" /var/log/secure* | awk '{print $11}' | sort | uniq -c
    echo "[!!!]登录失败的用户及次数如下:"  | $saveresult
    grep "Failed password" /var/log/secure* | awk '{print $9}' | sort | uniq -c
else
    echo "[*]日志中未发现登录失败的情况" | $saveresult
fi
printf "\n" | $saveresult

echo "-----------本机登录情况-----------------" | $saveresult
echo "正在检查本机登录情况....." | $saveresult
secure_log=$(find /var/log/ -type f \( -name "secure" -o -name "auth.log" -o -name "messages" \) 2>/dev/null | head -n1)
if [ -n "$secure_log" ]; then
    systemlogin=$(awk '/sshd:session.*session opened/ {print $1,$2,$3,$11}' "$secure_log")
    if [ -n "$systemlogin" ]; then
        echo "[*]本机登录情况:"  | $saveresult
        echo "$systemlogin" | $saveresult
        echo "[*]本机登录账号及次数如下:"  | $saveresult
        awk '/sshd:session.*session opened/ {print $11}' "$secure_log" | sort -nr | uniq -c
    else
        echo "[!!!]未发现在本机登录退出情况，请注意！！！" | $saveresult
    fi
else
    echo "[!!!]未找到安全日志文件，请注意！！！" | $saveresult
fi
printf "\n" | $saveresult



echo "------------message日志分析---------------" | $saveresult
echo "------------传输文件--------------------" | $saveresult
echo "正在检查传输文件....." | $saveresult
zmodem=$(grep "ZMODEM:.*BPS" /var/log/message*)
if [ -n "$zmodem" ]; then
	(echo "[!!!]传输文件情况:" && echo "$zmodem") | tee -a $danger_file | $saveresult
else
	echo "[*]日志中未发现传输文件" | $saveresult
fi
printf "\n" | $saveresult


echo "-----------cron日志分析---------------" | $saveresult

echo "------------定时下载-----------------" | $saveresult
echo "正在分析定时下载....." 
cron_download=$(grep "wget\|curl" /var/log/cron /var/log/cron.* 2>/dev/null)
if [ -n "$cron_download" ]; then
    (echo "[!!!]定时下载情况:" && echo "$cron_download") | $save_result_command
else
    echo "[*]未发现定时下载情况" | $saveresult
fi
printf "\n" | $saveresult


echo "------------定时执行脚本-----------------" | $saveresult
echo "正在分析定时执行脚本....." | $saveresult
cron_shell=$(grep -E "\.py$|\.sh$|\.pl$" /var/log/cron* 2>/dev/null)
if [ -n "$cron_shell" ]; then
    (echo "[!!!]发现定时执行脚本:" && echo "$cron_shell") | $saveresult
else
    echo "[*]未发现定时执行脚本" | $saveresult
fi
printf "\n" | $saveresult

echo "------------btmp日志分析----------------------" | $saveresult
echo "------------错误登录日志分析-----------------" | $saveresult 
echo "正在分析错误登录日志....." | $saveresult 
lastb=$(lastb 2>/dev/null)
if [ -n "$lastb" ]; then
    (echo "[*]错误登录日志如下:" && echo "$lastb") | $saveresult
else
    echo "[*]未发现错误登录日志" | $saveresult
fi
printf "\n" | $saveresult

echo "------------lastlog日志分析----------------------" | $saveresult
echo "------------所有用户最后一次登录日志分析-----------------" | $saveresult 
echo "正在分析所有用户最后一次登录日志....." | $saveresult 
lastlog=$(lastlog 2>/dev/null)
if [ -n "$lastlog" ]; then
    (echo "[*]所有用户最后一次登录日志如下:" && echo "${lastlog}") | $saveresult
else
    echo "[*]未发现所有用户最后一次登录日志" | $saveresult
fi
printf "\n" | $saveresult

echo "------------wtmp日志分析----------------------" | $saveresult
echo "------------所有登录用户分析-----------------" | $saveresult 
echo "正在检查历史上登录到本机的用户:" | $saveresult 
lasts=$(last | grep pts | grep -vw :0 2>/dev/null)
if [ -n "$lasts" ]; then
    (echo "[*]历史上登录到本机的用户如下:" && echo "$lasts") | $saveresult
else
    echo "[*]未发现历史上登录到本机的用户信息" | $saveresult
fi
printf "\n" | $saveresult


# Alias 后门检测
echo "正在检测 Alias 后门..." | $saveresult

# 列出当前用户的别名并搜索其中是否包含可疑命令
if [ -f ~/.bashrc ]; then
    echo "检查 ~/.bashrc..." | $saveresult
    grep -E 'alias[[:space:]]+(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' ~/.bashrc | $saveresult
fi

if [ -f ~/.bash_profile ]; then
    echo "检查 ~/.bash_profile..." | $saveresult
    grep -E 'alias[[:space:]]+(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' ~/.bash_profile | $saveresult
fi

if [ -f ~/.profile ]; then
    echo "检查 ~/.profile..." | $saveresult
    grep -E 'alias[[:space:]]+(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' ~/.profile | $saveresult
fi

# SSH 后门检测
echo "正在检测 SSH 后门..." | $saveresult

# 检查 SSH 配置文件是否包含可疑命令
if [ -f ~/.ssh/config ]; then
    echo "检查 ~/.ssh/config..." | $saveresult
    grep -E '(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' ~/.ssh/config  | $saveresult
fi

# SSH Wrapper 后门检测
echo "正在检测 SSH Wrapper 后门..." | $saveresult

# 检查 SSH 授权密钥文件是否包含可疑命令
if [ -f ~/.ssh/authorized_keys ]; then
    echo "检查 ~/.ssh/authorized_keys..." | $saveresult
    grep -E 'command="(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' ~/.ssh/authorized_keys | $saveresult
fi


# 检查特定目录中是否存在可疑文件
if [ -d /var/tmp ]; then
    echo "检查 /var/tmp..." | $saveresult
    ls -la /var/tmp | grep -E '(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' | $saveresult
fi

# 检查系统日志中是否包含可疑内容
echo "检查系统日志..." | $saveresult
if [ -f /var/log/auth.log ]; then
    grep -E '(wget|curl|bash|sh|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+)' /var/log/auth.log  | $saveresult
fi


echo "检查结束！！！" | $saveresult
