#tcpscan.py
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
         $python3 tcpscan -h 192.168.0.8,www.sina.com    #端口不给出时，执行0-1023 扫描

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
         模块名 tcpscan 小写字母
         常量名 大写字母
         变量名 模块变量名与函数名一样，都是小写，字间可以增加下划线以提高可读性。不加也无所谓。本项目中不加。
         类名   CapWord，单词首字母大写
    （2） 项目托管在github上，有一个程序员，两处开发地点。因此，需要有一个远程代码库。
         在本地盘上新建一个目录如：\codingproject，进入此目录：
         $git init
         $git clone https://github.com/727647912/tcpscan.git (拉代码，并更新working tree
         $cd tcpscan  (进入本地目录）
         拷贝其中的最新文件，到pycharm project中，开发。。。。
         一天结束时，拷贝pycharm project中的文件（tcpscan.py等）到上述目录中，并在上述目录中：
         $git 
1.5 测试
    单元测试，unittest


1.6 交付

1.7 持续进化


"""

import sys
import os

def usage():
    print ("\nUsage: python3 tcpscan -h [hosts | hostdomainname ]  [ -p port_number | port_range ]")
    print("hosts: could be a single ip or a list of ips or an ip range, for example: 192.168.0.1,192.168.0.10-192.168.0.20")
    print("hostdomainname: valid FQDN, for example: www.baidu.com")
    print("\n\n")



def main(argv):
#测试 argv第一元素一定是'-h', 否则给出使用提示
    if len(argv) <= 0 or argv[0] != "-h":
        usage()
        sys.exit(1)

    print (argv)


#----------------------------------  main ----------------------

if __name__ == "__main__" :
    main(sys.argv[1:])