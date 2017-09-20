# tcpscan.py
# -*- coding: utf-8 -*-
"""
1.需求
1.1 用户需求
    （1）系统应对指定IP范围内的主机进行TCP开放端口的检查；
    （2）主机可以以域名方式给出，也可以以IP方式给；



1.2 系统需求
    （1）要求以python模块方式实现；

    （2）要求至少有交互式命令行来实现；

         $python3 tcpscan -h www.htsc.com.cn -p 1-65535
         $python3 tcpscan -h www.htsc.com.cn -p 80,8080,21
         $python3 tcpscan -h 192.168.0.8-192.168.0.255,www.sina.com -p 21,80,8080,22,4899,135,445
         $python3 tcpscan -h 192.168.0.8,192.168.0.20 -p 21,80
         $python3 tcpscan -h 192.168.0.8,www.sina.com    # 端口不给出时，执行0-1023 扫描

    （3）要求有扫描报告。版本1.0报告为文本格式的。版本2.0报告支持以pdf格式输出。报告中的内容包括：
         起始日期，扫描目标，扫描范围，开放端口结论

    （4）运行环境： 单机(普通PC机，4G MEM）运行，windows, linux和macos
    （5）兼容性：python3
    （6）速度：单个目标（64K端口）的扫描完成时间30秒以内，同时可以支持最少20个线程
    （7）完成时间： 版本1.0 2周时间交付。
    （8）编码规范：PEP8

1.3 设计
    （1）原理

    （2）命令行输入接口设计：
         （A)参数的读取：sys.argv[0]脚本名，[1]... 参数，参数个数不限

    （3）单线程设计

1.4 编码
    （1）编码规范，PEP8中要求：
         模块名   tcpscan 小写字母
         常量名   大写字母
         变量名   模块变量名与函数名一样，都是小写，字间可以增加下划线以提高可读性。不加也无所谓。本项目中不加。
         类名     CapWord，单词首字母大写
         inline  注释要空至少两格，#之后要空一格
         运算符   前后要空一格，如" = "
         每行最长  120字符,太长用\换行

    （2） 项目托管在github上，有一个程序员，两处开发地点。因此，需要有一个远程代码库。
         远程代码库的创建和删除都需要手工登录到https://github.com上面操作。
         在本地盘上新建一个目录，这个目录可以存放所有需要远程同步的项目，如：\codingproject，进入此目录：
         $git init
         $git clone https://github.com/727647912/tcpscan.git (拉代码，并更新working tree
         $cd tcpscan  (进入本地目录）
         拷贝其中的最新文件，到pycharm project中，开发。。。。
         一天结束时，拷贝pycharm project中的文件（tcpscan.py等）到上述目录中，并在上述目录中：
         $git add tcpscan.py
         $git commit -m "2nd version"
         $git push -u origin master  (远程更新）


1.5 测试
    单元测试，unittest


1.6 交付

1.7 持续进化


"""

import sys
import re
import socket
import struct
import datetime

DEFAULT_PORT_LOWERLIMIT = 0
DEFAULT_PORT_UPPERLIMIT = 1023  # 如果没有给出 -p 则默认为 0-1023


def usage():
    print("\nUsage: \npython3 tcpscan.py -[h|H] [hosts | hostdomainname ]  [ -[p|P] port_number | port_range ]")
    print("hosts: could be a single ip or a list of ips or an ip range,\
for example: 192.168.0.1,192.168.0.10-192.168.0.20")
    print("hostdomainname: a valid FQDN, for example: www.baidu.com, case insensitive;")
    print("-p (optional), defaults to 0-1023 if not provided")
    print("port_number: valid from 0 to 65535")
    print("port_range syntax example: 0-20,21,22,8080")
    print("example: $python3 tcpscan.py -h www.sina.com,192.168.0.1,200.200.20.1-200.200.21.0 -p 21,8080")
    print("\n\n")


class TargetHosts():
    hostip_list = []  # 单个ip形式的目标主机列表
    hostdomain_list = []  # 如果以域名给出的主机，则把其名字和对应的解析出的ip放进此字典
    port_list = []

    @classmethod
    def remove_duplicate_and_sort(cls, filtertype="hostip"):
        if filtertype == "hostip":
            TargetHosts.hostip_list = list(set(TargetHosts.hostip_list))
            #print("Host ip after setting:{}".format(TargetHosts.hostip_list))
            TargetHosts.hostip_list.sort(key = TargetHosts.ip_int_cmp)  # 给个key函数，每个元素都会调用。
            #print("Host ip after remove_duplicate_and_sort:{}".format(TargetHosts.hostip_list))
            return True
        elif filtertype == "port":
            TargetHosts.port_list = list(set(TargetHosts.port_list))
            TargetHosts.port_list.sort()
            #print("Port list after remove_duplicate_and_sort:{}".format(TargetHosts.port_list))
            return True
        elif filtertype == "hostdomain":
            TargetHosts.hostdomain_list = list(set(TargetHosts.hostdomain_list))
            TargetHosts.hostdomain_list.sort()
            return True
        else:
            return False

    @classmethod
    def ip_int_cmp(cls,ip1):  #  两个ip的字符串表示，12.34.56.78
        return socket.ntohl(struct.unpack("I",socket.inet_aton(ip1))[0])


class CheckArgv():
    lowercase_argv = []

    def __init__(self, argv):
        # 转换并存贮所有参数为本类小写list
        for item in argv:
            CheckArgv.lowercase_argv.append(item.lower())

    def check(self):
        # 测试 argv第一元素一定是'-h', 否则给出使用提示

        if len(CheckArgv.lowercase_argv) <= 0:
            return False, "Invalid number of arguments!"

        if CheckArgv.lowercase_argv[0] != "-h":
            return False, "Argument must begin with -h or -H "

        if len(CheckArgv.lowercase_argv) < 2:
            return False, "host domain name or ip must be provided!"

        # 检查第二元素，应该是主机的描述。且是用逗号隔开的，连续数字或字母。

        ip_p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')

        domainname_p = re.compile('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')
        hostlist = CheckArgv.lowercase_argv[1].split(',')[:]
        for item in hostlist:
            if ip_p.match(item):  # found an ip
                TargetHosts.hostip_list.append(item)
                #print("TargetHosts {}".format(TargetHosts.hostip_list))
            elif domainname_p.match(item):  # found a domainname
                TargetHosts.hostdomain_list.append(item)
                #print("TargetHostsDomain {}".format(TargetHosts.hostdomain_list))
            elif re.search('-', item):  # is range expr?
                startip = item.split('-')[0]
                endip = item.split('-')[1]
                if ip_p.match(startip) and ip_p.match(endip):

                    startip_int = socket.ntohl(struct.unpack("I", socket.inet_aton(str(startip)))[0])
                    endip_int = socket.ntohl(struct.unpack("I", socket.inet_aton(str(endip)))[0])
                    if endip_int < startip_int:
                        startip_int, endip_int = endip_int, startip_int  # exchange
                    for item1 in range(startip_int, endip_int + 1):
                        ip_str = socket.inet_ntoa(struct.pack('I', socket.htonl(item1)))
                        TargetHosts.hostip_list.append(ip_str)
                else:  # not valid range
                    return False, "Invalid host range! [{}]".format(item)
                #print("TargetHosts {}".format(TargetHosts.hostip_list))
            else:
                return False, "Invalid hostname or host ip! [{}]".format(item)
        if len(CheckArgv.lowercase_argv) == 2:  # no -p
            for i in range(DEFAULT_PORT_LOWERLIMIT, DEFAULT_PORT_UPPERLIMIT + 1):
                TargetHosts.port_list.append(i)
            return True, "Arguments check completed."
        if len(CheckArgv.lowercase_argv) == 3:
            if CheckArgv.lowercase_argv[2] == "-p":
                return False, "Port number or port range cannot be null!"
            else:
                return False, "Unknow switch! [{}]".format(CheckArgv.lowercase_argv[2])
        if len(CheckArgv.lowercase_argv) == 4:  # ports
            portlist = CheckArgv.lowercase_argv[3].split(',')[:]
            print(portlist)
            int_p = re.compile('^[0-9]+$')
            for item in portlist:
                if int_p.match(item):
                    port_int = int(item)
                    if port_int <= 65535 and port_int >= 0:
                        TargetHosts.port_list.append(port_int)
                    else:
                        return False, "Port number should be no more than 65535, and not negative! [{}]".format(item)
                elif re.search('-', item):  # port range expr?
                    startport = item.split('-')[0]
                    endport = item.split('-')[1]
                    if int_p.match(startport) and int_p.match(endport):
                        startport_int = int(startport)
                        endport_int = int(endport)
                        if startport_int > 65535 or startport_int < 0 or endport_int > 65535 or endport_int < 0:
                            return False, "Port number should be no more than 65535, \
and not negative ! [{}]".format(item)
                        if startport_int > endport_int:
                            startport_int, endport_int = endport_int, startport_int
                        for i in range(startport_int, endport_int + 1):
                            TargetHosts.port_list.append(i)

                    else:
                        return False, "Invalid port range ![{}]".format(item)

                else:  # not a valid port or port range
                    return False, "Invalid port or port range ![{}]".format(item)

        return True, "Argument check completed."


def tcp_full_scanner(target_host, target_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   #   最传统的TCP socket
    s.settimeout(1)
    result = None
    try:
        s.connect((target_host,target_port))  # timeout type socket, return if everything ok, or raise socket.timeout
                                              # on timeout. or interrupted by a signal
        result = True                         # port alive!
    except socket.timeout:
        result = False                        # port not alive!
    finally:
        s.close()
        del s
        return result


def main(argv):
    # 测试命令行参数的有效性
    result, errormsg = CheckArgv(argv).check()
    if not result:
        print("Syntax Error: " + errormsg)
        usage()
        sys.exit(1)
    # 主机IP,domainname, port,排序，去重，端口排序
    if not TargetHosts.remove_duplicate_and_sort(filtertype="hostip"):
        print("Error while remove_duplicate_and_sort(hostip)")
        sys.exit(1)
    if not TargetHosts.remove_duplicate_and_sort(filtertype="port"):
        print("Error while remove_duplicate_and_sort(port)")
        sys.exit(1)
    if not TargetHosts.remove_duplicate_and_sort(filtertype="hostdomain"):
        print("Error while remove_duplicte_and_sor(hostdomain")
        sys.exit(1)


   # print(TargetHosts.hostip_list)
   # print(TargetHosts.hostdomain_list)
   # print(TargetHosts.port_list)
    print("")
    print("-"*80)
    print("Total Number of Targeted Hosts:{}".format(len(TargetHosts.hostip_list + TargetHosts.hostdomain_list)))
    print("    number of targeted host ips:{}".format(len(TargetHosts.hostip_list)))
    print("    number of targeted host domain names:{}".format(len(TargetHosts.hostdomain_list)))
    print("Selected ports number:{}".format(len(TargetHosts.port_list)))
    dt = datetime.datetime.today()
    print("Start scanning now [{:4d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}]\
......".format(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second))

    print("")

    # tcp full scan
    # (1) host ip
    for i in range(0, len(TargetHosts.hostip_list) ):
        for j in range(0, len(TargetHosts.port_list)):
            if tcp_full_scanner(TargetHosts.hostip_list[i],TargetHosts.port_list[j]):
                print("    [+]{0:20s} ==>     port:{1:6d}     \
Open!".format(TargetHosts.hostip_list[i],TargetHosts.port_list[j]) )

    print("")
    et = datetime.datetime.today()
    print("Scan Completed. [{:4d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}]\
".format(et.year, et.month, et.day, et.hour, et.minute, et.second))

# ----------------------------------  main ----------------------

if __name__ == "__main__":
    main(sys.argv[1:])
