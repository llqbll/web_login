#!/usr/bin/env python
# -*- coding:utf-8 -*-

import os
import urllib
import urllib2
import cookielib
from gzip import GzipFile
from StringIO import StringIO
import zlib
import sqlite3
import base64
import re
import json
import binascii, rsa
import socket

socket.setdefaulttimeout(10)

class ContentEncodingProcessor(urllib2.BaseHandler):
    """A handler to add gzip capabilities to urllib2 requests """

    # add headers to requests
    def http_request(self, req):

        req.add_header('User-Agent','Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.152 Safari/537.22')
        req.add_header("Accept-Encoding", "gzip, deflate")
        return req

    # decode
    def http_response(self, req, resp):
        old_resp = resp
        # gzip
        if resp.headers.get("content-encoding") == "gzip":
            gz = GzipFile(
                    fileobj=StringIO(resp.read()),
                    mode="r"
                )
            resp = urllib2.addinfourl(gz, old_resp.headers, old_resp.url, old_resp.code)
            resp.msg = old_resp.msg
        # deflate
        if resp.headers.get("content-encoding") == "deflate":
            gz = StringIO( deflate(resp.read()) )
            resp = urllib2.addinfourl(gz, old_resp.headers, old_resp.url, old_resp.code)  # 'class to add info() and
            resp.msg = old_resp.msg
        return resp

# deflate support
def deflate(data):   # zlib only provides the zlib compress format, not the deflate format;
    try:               # so on top of all there's this workaround:
        return zlib.decompress(data, -zlib.MAX_WBITS)
    except zlib.error:
        return zlib.decompress(data)

class my_login:

    encoding_support = ContentEncodingProcessor
    def __init__(self, username,pwd,cookie_file):#初始化urllib2，引入cookie
        self.uname = username
        self.passwd = pwd
        self.cookie_file = cookie_file

        self.cookie_jar = cookielib.MozillaCookieJar()
        cookie_support = urllib2.HTTPCookieProcessor(self.cookie_jar)
        httpHandler = urllib2.HTTPHandler(debuglevel=1)
        httpsHandler = urllib2.HTTPSHandler(debuglevel=1)
        self.opener = urllib2.build_opener(cookie_support, self.encoding_support,urllib2.HTTPHandler)
        urllib2.install_opener(self.opener)#设置 urllib2 的全局 opener

    def get_html(self,url):
        isopen = True
        while isopen:
            try:
                result = self.opener.open(url).read()
                isopen = False
            except:
                isopen = True
                time.sleep(0.2)
        return result

    def do_weibo_login(self):#RSA加密直接登录

        login_data = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'userticket': '1',
            'ssosimplelogin': '1',
            'vsnf': '1',
            'vsnval': '',
            'su': '',
            'service': 'miniblog',
            'servertime': '',
            'nonce': '',
            'pwencode': 'rsa2',
            'sp': '',
            'rsakv':'1330428213',
            'encoding': 'UTF-8',
            'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
        }
        servertime_url = 'http://login.sina.com.cn/sso/prelogin.php?entry=sso&callback=sinaSSOController.preloginCallBack&su=&rsakt=mod&client=ssologin.js(v1.4.4)'
        data = self.get_html(servertime_url)
        p = re.compile('\((.*)\)')
        try:
            json_data = p.search(data).group(1)
            data = json.loads(json_data)
            servertime = str(data['servertime'])
            nonce = data['nonce'].encode('UTF-8')
            pubkey = data['pubkey'].encode('UTF-8')
            rsakv = data['rsakv'].encode('UTF-8')
        except:
            print 'Get severtime and pubkey error!'
            return 0
        login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.4)'
        self.uname = urllib.quote(self.uname) #url格式编码
        self.uname = base64.encodestring(self.uname)[:-1] #base64加密username
        rsaPublickey = int(pubkey, 16)
        key = rsa.PublicKey(rsaPublickey, 65537) #创建公钥
        message = servertime + '\t' + nonce + '\n' + self.passwd #拼接明文 js加密文件中得到
        self.passwd = rsa.encrypt(message, key) #加密
        self.passwd = binascii.b2a_hex(self.passwd) #将加密信息转换为16进制

        login_data['servertime'] = servertime
        login_data['nonce'] = nonce
        login_data['su'] = self.uname
        login_data['sp'] = self.passwd
        login_data['rsakv'] = rsakv
        login_data = urllib.urlencode(login_data)

        req_login  = urllib2.Request(
            url = login_url,
            data = login_data
        )
        result = self.get_html(req_login)
        p = re.compile('location\.replace\(\"(.*?)\"\)')

        login_url = p.search(result).group(1)
        result = self.get_html(login_url)
        #print result
        try:
            p = re.compile('\((.*)\)')
            json_data = p.search(result).group(1)
            data = json.loads(json_data)
            result = str(data['result'])
            #print result
            if result == 'True':
                print 'RSA Login success!'
                self.cookie_jar.save(self.cookie_file,ignore_discard=True, ignore_expires=True)
                return 1
            else:
                print 'ID is down!'#账号登录错误次数太多,已有验证码要求
                return 0
        except:
            print '登录方式变了，重新研究吧！'
            return 0

    def weibo_login(self):#使用cookie登录,可以解决验证码问题

        if os.path.exists(self.cookie_file):
            try:
                cookie_load = self.cookie_jar.load(self.cookie_file,ignore_discard=True, ignore_expires=True)
            except cookielib.LoadError:
                print 'Loading cookies error'
                return self.do_weibo_login()#cookie过期使用RSA加密登录
        else:
            fileChrome = r'C:/Users/XXXXX/AppData/Local/Google/Chrome/User Data/Default/Cookies'#XXXX换为你的用户名win7
            conn = sqlite3.connect(fileChrome)
            conn.text_factory = str
            cur = conn.cursor()
            cur.execute("select host_key, path, secure, expires_utc, name, value from cookies")
            ftstr = ["FALSE","TRUE"]
            s = StringIO()
            s.write("""\
# Netscape HTTP Cookie File
# http://www.netscape.com/newsref/std/cookie_spec.html
# This is a generated file!  Do not edit.
""")
            for item in cur.fetchall():
                try:
                    s.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (item[0], ftstr[item[0].startswith('.')], item[1],ftstr[item[2]], item[3],item[4], item[5]))
                except UnicodeError:
                    continue
            s.seek(0)
            self.cookie_jar._really_load(s, '', True, True)
        url='http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack'
        text = self.get_html(url)
        #print text.decode("GBK").encode('UTF-8')
        try:
            p = re.compile('\((.*)\)')
            json_data = p.search(text).group(1)
            data = json.loads(json_data)
            result = str(data['result'])
            if result:
                print 'Cookies login success!'
                self.cookie_jar.save(self.cookie_file,ignore_discard=True, ignore_expires=True)
                return 1
            else:
                print 'Cookie error!,说实话应该到不了这一步，如果cookie有问题！换种方法登录吧'
                return self.do_weibo_login()#使用RSA加密登录
        except:
                print 'Cookie part expired!'#cookie认证过期，再次认证即可。
                #print text.decode("GBK").encode('UTF-8')
                p = re.compile('location\.replace\(\"(.*?)\"\)')
                login_url = p.search(text).group(1)
                #print login_url
                if login_url:
                    data = self.get_html(login_url)
                    #print data
                    p = re.compile('\((.*)\)')
                    try:
                        json_data = p.search(data).group(1)
                        data = json.loads(json_data)
                        result = str(data['result'])
                        if result:
                            print 'Again cookie login success!'
                            self.cookie_jar.save(self.cookie_file,ignore_discard=True, ignore_expires=True)
                            return 1
                        else:
                            print 'Cookie error!,说实话应该到不了这一步，如果cookie有问题！换种方法登录吧'
                            return self.do_weibo_login()#使用RSA加密登录
                    except:
                        print '登录方式变了，重新研究吧！'
                        return self.do_weibo_login()
                else:
                    print 'Cookie expired'
                    return self.do_weibo_login()

if __name__ == "__main__":

    username = 'xxx@sina.com'
    pwd = 'xxx'
    cookie_file  = 'cookie.dat'
    login = my_login(username,pwd,cookie_file)
    login_status = login.weibo_login()

    if login_status:
        url = 'http://weibo.com/aj/mblog/mbloglist?_wv=5&count=50&page=1&uid=1496878501'
        print login.get_html(url)
