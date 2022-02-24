# SunloginBatchRCE


向日葵RCE漏洞检测的相关脚本,仅用于合法情景下的漏洞检测验证，对于不合法的行为说不


sunloginRCEBatchScan.py 纯PY实现的批量主机+异步端口扫描+响应特征检测+Sunlogin漏洞检测


端口扫描和端口识别提取自infoport项目中的异步TCP端口扫描及tcp指纹识别项，也非常适合添加到任意的POC脚本中，给脚本增加批量IP和端口扫描功能。


usage: sunloginRCEBatchScan.py [-h] [-i IP] [-p PORTS] [-v] [-c CMD] [-x PROXIES]

    Sun Login RCE CMD ...

    optional arguments:
      -h, --help            show this help message and exit
      -i IP, --ip IP        输入目标IP、目标IP段、目标IP范围
      -p PORTS, --ports PORTS
                            输入目标端口、目标端口范围
      -v, --verify          是否验证Cookie获取和命令执行
      -c CMD, --cmd CMD     批量命令执行时使用的命令
      -x PROXIES, --proxies PROXIES
                            通过代理进行请求，支持Socks5和HTTP, 例如: http://127.0.0.1:8080 or socks5://127.0.0.1:1080
                            


usage: sunloginRCE.py [-h] [-i HOST] [-p PROXIES]

纯PY实现的Sunlogin漏洞验证,较简单的命令执行EXP

    optional arguments:
      -h, --help            show this help message and exit
      -i HOST, --host HOST  Specifies a ip:port
      -p PROXIES, --proxies PROXIES
                            Specify the requests proxy address, support Socks5 and HTTP, for example: http://127.0.0.1:8080 or
                            socks5://127.0.0.1:1080
                           
                           
Usage: sunloginRCE+.py [-h] [-i HOST] [-p PROXIES] [-g GET]


纯PY实现的Sunlogin漏洞验证,较简单的命令执行EXP，并且支持从本机向日葵配置文件中自动获取IP和端口号用于本机漏洞检测.(来自66的功能增加)


    optional arguments:
      -h, --help            show this help message and exit
      -i HOST, --host HOST  Specifies a ip:port
      -p PROXIES, --proxies PROXIES
                            Specify the requests proxy address, support Socks5 and HTTP, for example: http://127.0.0.1:8080 or
                            socks5://127.0.0.1:1080
      -g GET, --get GET     Get server ip:port,The default path:C:\ProgramData\Oray\SunloginClient\log




