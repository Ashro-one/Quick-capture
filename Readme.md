溯源工作中，会遇到很多反制到肉鸡，该脚本有利于在肉鸡上排查攻击者留下的痕迹，

Usge：

  sh Quick-capture.sh 

  输出结果在/tmp/{data} 文件

<img width="533" alt="image" src="https://github.com/Ashro-one/Quick-capture/assets/49979071/2b758c77-5c99-4d5a-8c99-3af8d5a7831f">

检查项：<br>
1.IP地址<br>
2.当前登录用户<br>
3.查看系统用户信息<br>
4.查看是否存在超级用户<br>
5.空口令账户检测<br>
6.新增用户检查<br>
7.新增用户组检查<br>
8.sudoers文件中用户权限<br>
9.检查各账户下的登录公钥<br>
10.网络连接和监听端口<br>
11.系统进程分析<br>
12.CPU内存异常<br>
13.检查历史命令<br>
14.定时任务分析<br>
15.登录、lastlog、wtmp日志分析<br>
16.检查历史登录IP记录<br>
17.后门简单排查<br>
