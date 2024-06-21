#!/usr/bin/env bash

echo "Linux肉鸡排查工具"
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

danger_file="/tmp/${date}_danger_file.txt"
log_file="/tmp/${date}_checkresult.txt"

echo "检查发现危险项，请注意:" > "$danger_file"

if [ "$(id -u)" != "0" ]; then
    echo "安全检查必须使用 root 账号，否则某些项无法检查。"
    exit 1
fi

saveresult="tee -a ${log_file}"

echo -e "\n************ 1.系统范围 ************\n" | $saveresult
echo "正在检查 IP 地址....." | $saveresult
echo "------------ IP 地址 -------------" | $saveresult
if [ -n "$ipadd" ]; then
    (echo "[*] 本机 IP 地址信息:" && echo "$ipadd") | $saveresult
else
    echo "[!!!] 本机未配置 IP 地址" | $saveresult
fi
printf "\n" | $saveresult

echo -e "************ 2.用户信息 ************\n" | $saveresult
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
    echo "[!!!] 除 root 外发现超级用户:" | tee -a "$danger_file" | $saveresult
else
    echo "[*] 未发现超级用户" | $saveresult
fi
printf "\n" | $saveresult

echo "------------ 空口令账户检测 --------------" | $saveresult
echo "正在检查空口令账户....." | $saveresult

empty_password_accounts=$(getent shadow | awk -F: '($2 == "") {print $1}')

if [ -n "$empty_password_accounts" ]; then
    echo "[!!!] 发现空口令账户:" | tee -a "$danger_file" | $saveresult
    echo "$empty_password_accounts" | tee -a "$danger_file" | $saveresult
else
    echo "[*] 未发现空口令账户" | $saveresult
fi
printf "\n" | $saveresult

echo "------------ 新增用户检查 --------------" | $saveresult
echo "正在检查新增用户....." | $saveresult

new_users=$(awk -F: '$3 >= 1000 && $3 != 65534' /etc/passwd)
if [ -n "$new_users" ]; then
    echo "[!!!] 发现以下新增用户:" | tee -a "$danger_file" | $saveresult
    echo "$new_users" | tee -a "$danger_file" | $saveresult
else
    echo "[*] 未发现新增用户" | $saveresult
fi
printf "\n" | $saveresult

echo "------------ 新增用户组检查 --------------" | $saveresult
echo "正在检查新增用户组....." | $saveresult

new_groups=$(awk -F: '$3 >= 1000' /etc/group)
if [ -n "$new_groups" ]; then
    echo "[!!!] 发现以下新增用户组:" | tee -a "$danger_file" | $saveresult
    echo "$new_groups" | tee -a "$danger_file" | $saveresult
else
    echo "[*] 未发现新增用户组" | $saveresult
fi
printf "\n" | $saveresult

echo "------------ 检查sudoers文件中用户权限 --------------" | $saveresult
echo "正在检查sudoers文件中用户权限....." | $saveresult

sudoers_users=$(visudo -c 2>&1 | grep -E '^[^#]*[[:space:]]ALL=.*NOPASSWD' | awk '{print $1}')

if [ -n "$sudoers_users" ]; then
    echo "[!!!] 发现具有 NOPASSWD 权限的用户:" | tee -a "$danger_file" | $saveresult
    echo "$sudoers_users" | tee -a "$danger_file" | $saveresult
else
    echo "[*] 未发现具有 NOPASSWD 权限的用户" | $saveresult
fi
printf "\n" | $saveresult

echo "------------ 检查各账户下登录公钥 --------------" | $saveresult
echo "正在检查各账户下登录公钥....." | $saveresult

home_dirs=$(getent passwd | cut -d: -f6)

for dir in $home_dirs; do
    authorized_keys_file="$dir/.ssh/authorized_keys"
    if [ -f "$authorized_keys_file" ]; then
        echo "[!!!] 在用户 $dir 下发现登录公钥：" | tee -a "$danger_file" | $saveresult
        cat "$authorized_keys_file" | tee -a "$danger_file" | $saveresult
    fi
done
printf "\n" | $saveresult

echo "------------ 检查历史登录 IP 记录 --------------" | $saveresult
echo "正在检查历史登录 IP 记录....." | $saveresult

if [ -f "/var/log/auth.log" ]; then
    login_ips=$(grep -E "sshd.*Accepted" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr)
elif [ -f "/var/log/secure" ]; then
    login_ips=$(grep -E "sshd.*Accepted" /var/log/secure | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr)
else
    login_ips=""
    echo "[!!!] 未找到系统日志文件 (auth.log 或 secure)，无法检查历史登录 IP 记录。" | $saveresult
fi

if [ -n "$login_ips" ]; then
    echo "[*] 历史登录 IP 记录:" | $saveresult
    echo "$login_ips" | $saveresult
else
    echo "[*] 未发现历史登录 IP 记录" | $saveresult
fi
printf "\n" | $saveresult

echo "------------ 检查历史命令 --------------" | $saveresult
echo "正在检查历史命令....." | $saveresult

for home in /home/*; do
    history_file="$home/.bash_history"
    if [ -f "$history_file" ]; then
        user=$(basename "$home")
        echo "[*] 用户 $user 的历史命令:" | $saveresult
        cat "$history_file" | $saveresult
        printf "\n" | $saveresult
    fi
done

root_history_file="/root/.bash_history"
if [ -f "$root_history_file" ]; then
    echo "[*] root 用户的历史命令:" | $saveresult
    cat "$root_history_file" | $saveresult
    printf "\n" | $saveresult
fi

# 你可以在这里继续添加其他检查项目，如文件系统完整性、网络连接、服务状态等

echo "系统安全检查完成。" | $saveresult
echo "详细日志保存在：${log_file}" | $saveresult
echo "危险项列表保存在：${danger_file}" | $saveresult

exit 0
