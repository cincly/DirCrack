#! /usr/bin/env python3
# -*- coding: utf-8 -*- 

"""
web目录扫描工具
    - 协程扫描
    - 扫描速率控制
    - 循环扫描，均分扫描目录时产生的流量
    - 自动探测目录不存在时的响应格式
    - 可选的手动指定目录不存在时的响应格式

@Author: clowndmn@gmail.com
"""

import io
import sys
import uuid
import urllib3
import httpx
import argparse
import asyncio

urllib3.disable_warnings()

args = None
global_proxy = {
    'http': None,
    'https': None
}
global_head = {
    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/79.0.3945.130 Safari/537.36"
}
global_output = None
invalid_format_list = []  # 无效页面的格式  [ (status_code, include_content), (status_code, include_content), ... ]

max_number = 1  # 最多遍历目录的数量
now_number = 1  # 当前遍历目录的个数
COLOR_GREEN = "\033[1;32;36m"
COLOR_RED = "\033[1;31;40m"
COLOR_DEFAULT = "\033[0m"


def hlprint(msg, clr=COLOR_GREEN, **kwags):
    print("{}{:80}{}".format(clr, msg, COLOR_DEFAULT), **kwags)


def banner():
    print("""    .___.__                             __           
  __| _/|__|______   ________________  |  | __ ____  
 / __ | |  \_  __ \_/ ___\_  __ \__  \ |  |/ // __ \ 
/ /_/ | |  ||  | \/\  \___|  | \// __ \|    <\  ___/ 
\____ | |__||__|    \___  >__|  (____  /__|_ \\___  >
     \/                 \/           \/     \/    \/ 
     
    """)


def init():
    global args
    global global_head
    global global_proxy
    global global_output

    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", type=str, help="Base URL to scan")
    parser.add_argument("-fu", "--file-url", dest="file_url", type=str, help="Base URL from File")
    parser.add_argument("-d", "--dic", dest="dic", default="./dic/common.txt",
                        help="Default dictionary: ./dic/common.txt")
    parser.add_argument("-X", "--ext", dest="ext", action="append",
                        type=str, help="Amplify search with extensions")

    parser.add_argument("-A", "--agent", dest="agent", type=str, help="Specify your custom UserAgent")
    parser.add_argument("-H", "--Head", dest="head", action="append",
                        type=str, help="Add a custom header to the HTTP request")

    parser.add_argument("-p", "--proxy", dest="proxy", type=str, help="Scan using a proxy")
    parser.add_argument("-r", "--rate", dest="rate", type=int, default=900, help="Scan rate(Minute)")
    parser.add_argument("--allow-redirect", dest="allow_redirect", default=False,
                        action="store_true", help="Allow redirect")
    parser.add_argument("-o", "--output-file", dest="output", type=str, help="Save output to disk")
    parser.add_argument("--invalid-page", dest="invalid_pages", type=str, action="append",
                        help="Invalid page format: status_code:content")
    parser.add_argument("--time-out", dest="timeout", type=int, default=20, help="Default: 20")

    args = parser.parse_args()

    if not args.url and not args.file_url:
        parser.print_help()
        return

    if args.agent:
        global_head['User-Agent'] = args.agent
    if args.head:
        for head in args.head:
            ceils = [i.strip() for i in str(head).split(':')]
            if len(ceils) != 2:
                continue
            global_head[ceils[0]] = ceils[1]
    if args.proxy:
        global_proxy['http'] = args.proxy
        global_proxy['https'] = args.proxy

    if args.output:
        global_output = open(args.output, "w")

    if args.invalid_pages:
        for invalid_page in args.invalid_pages:
            ceils = [i.strip() for i in str(invalid_page).split(":")]
            if len(ceils) != 2:
                hlprint("[-] error params: {}".format(args.invalid_pages), COLOR_RED)
                sys.exit(-1)
            status_code, content = ceils
            if status_code and not status_code.isnumeric():  # 若设置状态码，一定要是数值型才可以
                hlprint("[-] error params: {}".format(args.invalid_pages), COLOR_RED)
                sys.exit(-1)
            invalid_format_list.append((status_code, content))


class Site(object):
    class IdentifyField(object):
        def __init__(self, status_code, content_length):
            """
            标识字段（标识响应包是否有效）
            暂时只用这两个字段来标识，还有可能会有其他情况，比如  not found ....
            后续可能会添加关键字匹配
            :param status_code:  状态码
            :param content_length:  响应包长度
            """
            self.status_code = status_code
            self.content_length = content_length

    def __init__(self, site: str):
        site = site.strip()
        if not site.startswith('http'):
            site = "http://{}".format(site)
        if not site.endswith("/"):
            site = "{}/".format(site)

        self.timeout = args.timeout
        self.site = site
        self.valid = True  # 该链接是否有效，若无效，则不检查该链接
        # 未找到页面时的标识字段
        self.verify_normal = Site.IdentifyField(404, None)  # 默认
        self.verify_dot = None  # 以 . 开头的随机url，如果返回内容跟普通的不一样，则使用这个进行标识
        self.verify_exts = []  # 以不同后缀开始的url，如果返回内容跟普通的不一样，则用这个标识（这个是数组）

        uid = uuid.uuid1()
        client = httpx.Client(headers=global_head, timeout=5, verify=False, proxies=global_proxy)

        try:
            """
            normal detection
            """
            rest_normal_1 = client.get("{}{}".format(site, uid.hex), allow_redirects=args.allow_redirect)
            rest_normal_2 = client.get("{}{}".format(site, uid.time), allow_redirects=args.allow_redirect)

            # the page not found meets this condition -> status_code
            if rest_normal_1.status_code == rest_normal_2.status_code:
                self.verify_normal.status_code = rest_normal_1.status_code
            # the page not found meets this condition -> content_length
            if len(rest_normal_1.content) == len(rest_normal_2.content):
                self.verify_normal.content_length = len(rest_normal_1.content)

            # 若设置了该参数，则不再进行规则探测。当设置了这个参数后，上面的普通规则探测实际上并没有实际作用
            # 只不过是用来探测一下要测试的目标是否存活
            if invalid_format_list:
                return

            """
            dot detection
            """
            rest1 = client.get("{}.{}".format(site, uid.hex), allow_redirects=args.allow_redirect)
            rest2 = client.get("{}.{}".format(site, uid.time), allow_redirects=args.allow_redirect)

            verify_status_code = self.verify_normal.status_code
            verify_content_length = self.verify_normal.content_length

            if rest1.status_code == rest2.status_code:
                verify_status_code = rest1.status_code
            if len(rest1.content) == len(rest2.content):
                verify_content_length = len(rest1.content)

            # 与普通的响应不一致时，再设置
            if verify_status_code != self.verify_normal.status_code or \
                    verify_content_length != self.verify_normal.content_length:
                self.verify_dot = Site.IdentifyField(verify_status_code, verify_content_length)

            """
            ext detection(compare with dot detection)
            """
            ext = [i.strip() for i in args.ext] if args.ext else None
            if ext:  # 只有设置了非空后缀时，才需要设置
                for e in ext:
                    if e == '':
                        continue
                    if not str(e).startswith("."):
                        e = ".{}".format(e)
                    rest1 = client.get("{}{}{}".format(site, uid.hex, e), allow_redirects=args.allow_redirect)
                    rest2 = client.get("{}{}{}".format(site, uid.time, e), allow_redirects=args.allow_redirect)

                    verify_status_code = self.verify_normal.status_code
                    verify_content_length = self.verify_normal.content_length

                    if rest1.status_code == rest2.status_code:
                        verify_status_code = rest1.status_code
                    if len(rest1.content) == len(rest2.content):
                        verify_content_length = len(rest1.content)
                    # 与普通的响应不一致时，在设置
                    if verify_status_code != self.verify_normal.status_code or \
                            verify_content_length != self.verify_normal.content_length:
                        self.verify_exts.append(Site.IdentifyField(verify_status_code, verify_content_length))

        except Exception as e:
            hlprint("[-] {} open exception: {}".format(site, e), COLOR_RED)
            self.valid = False

    async def check(self, path, msg: dict) -> bool:
        """
        判断是否存在这个路径
        :param path:
        :param msg: 用来返回一些信息
        :return: true or false
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False, proxies=global_proxy,
                                         headers=global_head) as client:
                rest = await client.get("{}{}".format(self.site, path), allow_redirects=args.allow_redirect)
                msg['rest'] = rest

                if invalid_format_list:  # 若设置了该参数，则直接以该参数中的内容为准
                    for invalid_status_code, invalid_text in invalid_format_list:
                        # 状态码判断
                        if invalid_status_code and int(invalid_status_code) != rest.status_code:
                            continue
                        # 响应内容包含判断
                        if invalid_text and invalid_text not in rest.text:
                            continue
                        # 若状态码与响应内容均匹配，说明这个url是无效的，返回False
                        return False
                    return True  # 验证通过
                else:
                    #  normal 判断
                    if rest.status_code == self.verify_normal.status_code and \
                            (not self.verify_normal.content_length or
                             len(rest.content) == self.verify_normal.content_length):
                        return False

                    # 后缀判断
                    if self.verify_exts:
                        for verify_ext in self.verify_exts:
                            if rest.status_code == verify_ext.status_code and \
                                    (not verify_ext.content_length or
                                     len(rest.content) == verify_ext.content_length):
                                return False

                    # . 判断
                    if self.verify_dot:
                        if rest.status_code == self.verify_dot.status_code and \
                                (not self.verify_dot.content_length or
                                 len(rest.content) == self.verify_dot.content_length):
                            return False

                return True
        except TimeoutError:
            pass
        except Exception as e:  # 访问异常，直接返回false
            hlprint("[-] {}{} check error: {}".format(self.site, path, e), COLOR_RED)
        return False


async def worker(site: Site, name, ext: str):
    global now_number

    if ext != '' and not ext.startswith('.'):
        ext = ".{}".format(ext)
    path = "{}{}".format(name, ext)

    msg = {}
    if await site.check(path, msg):
        rest = msg['rest']
        hlprint("[+] {}{} (CODE:{}|SIZE:{})".format(site.site, path, rest.status_code, len(rest.content)),
                clr=COLOR_RED)
        if isinstance(global_output, io.TextIOWrapper):
            global_output.write("{}{} (CODE:{}|SIZE:{})\n".format(site.site, path, rest.status_code, len(rest.content)))
    else:
        hlprint("[{}/{}] scan: {}{}".format(now_number, max_number, site.site, path), clr=COLOR_GREEN, end='\r',
                flush=True)
    now_number += 1


async def scan():
    global max_number

    url = args.url
    file_url = args.file_url
    dic = args.dic
    rate = args.rate
    ext = args.ext if args.ext is not None else ['']
    ext = [i.strip() for i in ext]
    ext = set(ext)

    if rate < 0 or rate > 100000:
        print("[-] error rate: {}".format(rate))
        sys.exit(-1)

    interval = 60.0 / rate  # 计算间隔时间

    dics = []
    with open(dic) as f_dic:
        for name in f_dic:
            dics.append(name.strip())

    sites = []
    if url:
        site = Site(url)
        if not site.valid:  # 待测站点无效，直接结束
            sys.exit(-1)
        sites.append(site)
    elif file_url:
        with open(file_url) as f_url:
            for u in f_url:
                site = Site(u)
                if site.valid:
                    sites.append(site)
    else:
        hlprint("[-] url or file_url must choose one!", COLOR_RED)
        sys.exit(-1)

    if len(sites) == 0:
        hlprint("[-] not found the valid url!", COLOR_RED)

    max_number = len(dics) * len(ext) * len(sites)

    for e in ext:  # 后缀
        for d in dics:  # 目录
            for s in sites:  # site
                wk = worker(s, d, e)
                asyncio.get_event_loop().create_task(wk)
                await asyncio.sleep(interval)


def start():
    init()
    assert isinstance(args, argparse.Namespace)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(scan())

    all_tasks = asyncio.Task.all_tasks()
    group = asyncio.gather(*all_tasks, return_exceptions=True)
    loop.run_until_complete(group)
    loop.close()


if __name__ == '__main__':
    try:
        start()
    except KeyboardInterrupt:
        hlprint("\nShutting Down!")
        sys.stdout = None
        sys.stderr = None
    else:
        hlprint("\nOVER!")
    finally:
        if isinstance(global_output, io.TextIOWrapper):
            global_output.close()
