#!/usr/bin/env python3

import sys
import time
import queue
import os.path
import random
import argparse
import requests
import threading

from checkWAF import *
from resources.banner import banner
from resources.useragents import user_agents
from resources.colors import red, white, green, blue, yellow, reset
import whois
from urllib.parse import urlparse
import socket
import nmap
import sys
import os
import argparse
import requests
import socket
import re
import whois
import nmap
import json
import zlib
import random
import string
import colorama
from tqdm import tqdm
import multiprocessing
import sys



def perform_whois_query(domain_name):
    print("++++++++ whois查询 ++++++++++")
    try:
        w = whois.whois(domain_name)
        print("域名: ", w.domain_name)
        print("注册商: ", w.registrar)
        print("注册日期: ", w.creation_date)
        print("到期日期: ", w.expiration_date)
        print("WHOIS服务器: ", w.whois_server)
        print("注册人: ", w.name)
        print("联系邮箱: ", w.email)
        print("联系地址: ", w.address)
    except whois.parser.PywhoisError as e:
        print("查询失败:", str(e))

    print("++++++++++++++++++++++++++")
    print()


def scan_ports(ip):
    print("++++++++ 端口扫描 ++++++++++")

    # 创建PortScanner对象。必须安装Nmap
    nm = nmap.PortScanner()

    # 可以3个参数。主机，端口，参数（例如：-sP）
    nm.scan(ip, '1-1024')

    # 以列表形式返回scan（）函数指定的主机信息
    for host in nm.all_hosts():
        print('--------------------------')

        # 主机IP和名称
        print('Host:{0} ({1})'.format(host, nm[host].hostname()))

        # 主机状态，处于服务中为up
        print('State:{0}'.format(nm[host].state()))

        # 以列表形式显示主机中扫描到 所有协议
        for proto in nm[host].all_protocols():
            print('--------------------------')
            print('Protocal:{0}'.format(proto))

            # 以集合形式返回不同主机与协议中开发的端口信息
            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                # 显示端口详细信息
                print('port:{0}\tstate:{1}'.format(port, nm[host][proto][port]))

    print("++++++++++++++++++++++++++")
    print()



# 多地ping
def n_ping(key):
    print("\033[1;32m[N_ping]:\033[0m")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded; "
    }

    callback_lib = [
        "jQuery111306167052211460833_1630908921895",
        "jQuery111306167052211460833_1630908921896",
        "jQuery111306167052211460833_1630908921897",
        "jQuery111306167052211460833_1630908921898",
        "jQuery111306167052211460833_1630908921899",
    ]

    node = {
        "安徽合肥[移动]": "fc778772-3967-4b70-be93-9045f310e16c",
        "安徽合肥[联通]": "66426ad9-99d9-471f-b55f-c270cc3fc878",
        "浙江扬州[多线]": "4a40427f-502e-4a85-8752-980f2d8bbae1",
        "广东东莞[电信]": "cd4e7631-8427-41b6-8e44-869a70a04b20",
        "山东济南[联通]": "4d7637d7-4950-4b79-9741-c397789bcf05",
        "辽宁大连[电信]": "e1d5b78f-6ba5-485d-a4dd-54dc546b991a",
        "上海[多线]": "a936bb02-6b19-4da5-9c82-e8bb68fcfbea",
        "北京[多线]": "463cd3ff-65cb-4b5a-8c77-555ef43b6612",
        "内蒙古呼和浩特[多线]": "8c0b720b-e1a1-4422-a948-e8d7ec7e4906",
        "山东枣庄[联通]_1": "9e980285-f696-4478-a645-fc1e5a76ed47",
        "山东枣庄[联通]_2": "2573ad6d-082d-479d-bab6-49f24eca4e47",
        "江苏徐州[电信]": "92dad4c3-9bc3-4f71-a0b0-db9376613bb2",
        "辽宁沈阳[多线]": "07f2f1cc-8414-4557-a8c1-27750a732f16",
        "新疆哈密[电信]": "9bc90d67-d208-434d-b680-294ae4288571",
        "云南昆明[电信]": "14ef4fcf-3712-4971-9c24-0d1657751022",
        "中国香港_1": "cdcf3a45-8366-4ab4-ae80-75eb6c1c9fca",
        "中国香港_2": "a0be885d-24ad-487d-bbb0-c94cd02a137d",
        "中国台湾": "483bad95-d9a8-4026-87f4-7a56501bf5fd",
        "韩国CN2": "1f4c5976-8cf3-47e7-be10-aa9270461477",
        "韩国CN联通_1": "dc440a55-1148-480f-90a7-9d1e0269b682",
        "韩国CN联通_2": "6cd2450a-d73d-40c7-96ce-afc20540eeea",
        "美国_1": "737831b4-95e1-445f-a981-c1333faf88bd",
        "美国_2": "e4f8c1ef-2160-47f7-850f-6446ca0680b4",
        "德国": "d9041619-7d90-42ea-9811-2b2fe11cb2b0",
    }
    ip_value = ""
    keys = tqdm(node.keys(), ncols=75)
    keys.set_description(colorama.Fore.BLUE + "进度条")
    for n in keys:
        url = "http://ping.chinaz.com/iframe.ashx?t=ping&callback={}".format(random.choice(callback_lib))
        data = "guid={}&host={}&ishost=0&isipv6=0&encode=g4LFw6M5ZZa9pkSC|tGN8JBHp|lHVl2x&checktype=0".format(
            node[n], key)
        res = requests.post(url=url, headers=headers, data=data)
        res_node = res.text
        node_value = re.findall("\({(.*?)}\)", res_node, re.S)
        if 1:
            keys.write('\033[1;31m{}:The node timed out！\033[0m'.format(n))
        else:
            keys.write(colorama.Fore.BLUE + '{}:{}'.format(n, node_value[0]))
            ip_value += node_value[0]
            keys.write('\033[1;31m{}:The node timed out！\033[0m'.format(n))
    set_ip = set(re.findall("ip:'(.*?)',", ip_value, re.S))
    if len(set_ip) > 1:
        print("\033[1;31m经检测该域名可能使用CDN加速，共发现{}个节点：{}\033[0m".format(len(set_ip), ",".join(set_ip)))
    else:
        print("\033[1;34m经检测该域名未使用CDN加速，仅发现1个节点：{}\033[0m".format(",".join(set_ip)))


def subdomain_scan(domain, dictionary_file):
    subdomains = []

    with open(dictionary_file, 'r') as file:
        for line in file:
            subdomain = line.strip()
            url = f'http://{subdomain}.{domain}'

            try:
                response = requests.get(url)
                if response.status_code == 200:
                    subdomains.append(subdomain)
                    print(subdomain+"."+domain)
                    if len(subdomains)==3:
                        break
            except requests.exceptions.RequestException:
                pass

    return subdomains


print(banner)



def main(args):
    parsed_url = urlparse(args.url)
    domain = parsed_url.netloc
    perform_whois_query(domain)

    print("++++++++ 域名反查ip ++++++++++")
    try:
        ip_address=""
        ip_address = socket.gethostbyname(domain)
        print(domain+"域名反查ip为："+ip_address)
    except socket.error as e:
        print("域名解析失败:", str(e))
    print("++++++++++++++++++++++++++")
    print()

    print("++++++++ 检测是否存在waf ++++++++++")
    headers = {  # HTTP 头设置
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20',
        'Referer': 'http://www.google.com',
        'Cookie': 'whoami=wyscan_dirfuzz',
    }
    try:
        checkWaf(url=args.url, header=headers,  timeout=3, allow_redirects=True)
    except:
        pass
    print("++++++++++++++++++++++++++")
    print()

    if ip_address!="":
        scan_ports(ip_address)


    print("++++++++ 多地ping ++++++++++")

    n_ping(parsed_url)

    print("++++++++++++++++++++++++++")
    print()

    print("++++++++ 子域名探测 ++++++++++")
    parts = domain.split('.')

    # 提取根域名和二级域名
    if len(parts) > 2:
        root_domain = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2])
    else:
        root_domain = domain
        subdomain = ''
    result = subdomain_scan(root_domain, 'subdomain.txt')
    print(result)
    print("++++++++++++++++++++++++++")
    print()




    extensions = []
    if args.extensions:
        x = args.extensions.split(',')
        for i in x:
            extensions.append(i.strip())
    else:
        pass
    for i in range(args.threads):
        t = threading.Thread(target=dirBruter, args=(args, extensions))
        t.daemon = True
        t.start()
        while True:
            t.join(1)
            if not t.is_alive():
                break
            time.sleep(2)


def valid_wordlist(parser, args):
    if not os.path.exists(args):
        print(f"{white}[{red}WARNING{white}] The file {green}{args}{white} does not exist{reset}")
    else:
        print(f"{white}> Wordlist: {green}{args}{reset}")
        wordlist_file = open(args, 'r')
        return wordlist_file


def save_found_results(target_url):
    ts = time.localtime()
    timestamp = time.strftime("%H:%M:%S", ts)
    file = open(f'dB_output.txt', 'a')
    file.write(f'[{timestamp}] : {target_url}\n')


def dirBruter(args, extensions=None):
    raw_url = args.url
    last_char = raw_url[-1]
    if last_char == '/':
        url = raw_url[:-1]
    else:
        url = raw_url
    wordlist = args.wordlist
    words = queue.Queue()
    for word in wordlist:
        word = word.rstrip()
        words.put(word)
    found_url = []
    while not words.empty():
        attempt = words.get()
        attempt_list = []
        if "." not in attempt:
            attempt_list.append(f"/{attempt}/")
        else:
            attempt_list.append(f"/{attempt}")
        if extensions:
            for extension in extensions:
                attempt_list.append(f"/{attempt}{extension}")
        for brute in attempt_list:
            try:

                target_url = f"{url}{brute}"
                headers = {"User-Agent": f"{random.choice(user_agents)}"}
                response = requests.get(target_url, headers=headers, timeout=5)
                if response.status_code == 200:
                    if args.output:
                        save_found_results(target_url)
                    found_url.append(target_url)
                    print(f"{white}[{green}FOUND{white}] {response.status_code}: {green}{target_url}{reset}")

                elif response.status_code == 404:
                    if args.verbose:
                        print(f"{white}[{red}NOT FOUND{white}] {response.status_code}: {red}{target_url}{reset}")
                    else:
                        pass
                else:
                    if args.verbose:
                        print(f"{white}[{blue}UNKNOWN{white}] {response.status_code}: {blue}{target_url}{reset}")
                    else:
                        pass

            except requests.Timeout:
                if args.verbose:
                    print(f"{white}[{yellow}TIMEOUT{white}] Request timed out: {yellow}{target_url}{reset}")

            except Exception as e:
                if args.verbose:
                    print(f"{white}[{red}ERROR{white}] An error occurred: {red}{e}{reset}")


parser = argparse.ArgumentParser(
    description=f'{white}JustTest — by Zhangkaibin{reset}',
    epilog=f'{white}JustTest is a multi-function information gathering scanner that can perform whois, domain name reverse-lookup ip, port scanning (based on python-nmap), multi-place ping(judging CDN, based on webmaster API and crawls), dictionary-based directory scanning and subdomain scanning, waf detection (construction of malicious payload){reset}')
parser.add_argument('-t', '--threads', type=int, help='number of threads (default is 1)', metavar='<threads>',
                    default=1)
parser.add_argument('-u', '--url', type=str, help='target url', metavar='<url>', required=True)
parser.add_argument('-w', '--wordlist', help="wordlist file/path to wordlist", metavar='<wordlist>', required=True,
                    type=lambda x: valid_wordlist(parser, x))
parser.add_argument('-o', '--output', help='save found results to a file', action='store_true')
parser.add_argument('-v', '--verbose', help='verbose output (show network logs/errors)', action='store_true')
parser.add_argument('-e', '--extensions', help='extensions (example ".php,.exe,.bak")', metavar='<extensions>')
args = parser.parse_args()
if __name__ == '__main__':
    try:
        print(f"{white}> Target: {green}{args.url}{reset}")
        print(f"{white}-{reset}" * 41)
        main(args)
    except KeyboardInterrupt:
        if args.verbose:
            print(f"{white}[{red}CTRLC{white}] Exiting...{reset}")
            time.sleep(1)
            sys.exit(1)
        sys.exit(1)

    except Exception as e:
        if args.verbose:
            print(f"{white}[{red}ERROR{white}] An error occurred: {red}{e}{reset}")