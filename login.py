# -*- coding: utf-8 -*-
from login_setting import ua,message
import requests
import base64
import rsa
import random
import time
import re
import binascii
import bs4
import json
import http.cookiejar as cookielib


session = requests.session()
session.cookies = cookielib.LWPCookieJar(filename='cookies.txt')
ua = random.choice(ua)
now = time.time()
now = (int(now*1000))
su = base64.b64encode(bytes(message['name'],encoding='utf-8'))


def get_param():
    '''起始请求，用来获取rsa加密所需数据'''
    try:
        url = 'https://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=' \
              '{0}&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.19)&_={1}'.format(su,now)
        response = requests.get(url,headers={'User-Agent':ua})
        return response
    except:
        print('登录超时，位置：get_param')


def rsa_encryption(response):
    '''解析rsa加密所需数据，对用户密码进行加密
       并生成post请求数据'''
    try:
        servertime = re.match('.*time":?([\d]+),"pcid',response.text).group(1)
        nonce = re.match('.*nce":"(.*)","pubkey',response.text).group(1)
        pubkey = re.match('.*key":"(.*)","rsakv',response.text).group(1)
        rsa_e = int('10001',16)  # 0x10001
        pw_string = str(servertime) + '\t' + str(nonce) + '\n' + str(message['password'])
        key = rsa.PublicKey(int(pubkey, 16), rsa_e)
        pw_encypted = rsa.encrypt(pw_string.encode('utf-8'), key)
        password = binascii.b2a_hex(pw_encypted)#将二进制编码转化为ascii/hex
        password = str(password,encoding='utf-8')
        data = {
            'entry': 'weibo',
            'gateway': '1',
            'from': 'null',
            'savestate': '0',
            'qrcode_flag': 'false',
            'useticket': '1',
            'pagerefer': 'https://www.baidu.com/link?url=q_xHGEAkSjGBzN_PIVDQ4WbfZZlryEo8qXpz0BtEN8W&wd=&eqid=bdfe64670001b8b9000000065abbb38c',
            'vsnf': '1',
            'su': su,
            'service': 'miniblog',
            'servertime': servertime,
            'nonce': nonce,
            'pwencode': 'rsa2',
            'rsakv': '1330428213',
            'sp': password,
            'sr': '1536*864',
            'encoding': 'UTF-8',
            'prelt': '35',
            'url': 'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
        }
        return data
    except:
        print('rsa加密失败，位置：rsa_encryption')


def login_start(data):
    '''登录第一步，获取跳转链接'''
    try:
        url = 'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)'
        response = requests.post(url,headers={'User-Agent':ua},data=data)
        temp = response.content.decode('gb2312')
        url2 = json.loads(temp.split('(')[1].split(')')[0])
        return url2
    except:
        print('登录起始请求失败（maybe请求超时），位置：login_start')


def login_second(url):
    '''登录第二步，继续获取跳转链接
       并获取cookie保存且加载'''
    try:
        response = session.get(url,headers={'User-Agent':ua})
        session.cookies.save()
        session.cookies.load(ignore_discard=True)
        url_html = bs4.BeautifulSoup(response.content.decode('gb2312'),'html5lib')
        url_text = url_html.get_text()
        url_pro = url_text.split()[26]
        url = re.match('.*location\.replace\(\'(.*)\'\).*',url_pro).group(1)
        return url
    except:
        print('登录二次跳转请求失败（maybe请求超时），位置：login_second')


def login_third(url):
    '''登录第三步，获取最终参数'''
    try:
        response = session.get(url,headers={'User-Agent':ua})
        param_html = bs4.BeautifulSoup(response.content.decode('gb2312'),'html5lib')
        param_json = json.loads(param_html.get_text().split('(')[1].split(')')[0])
        param = param_json['userinfo']['userdomain']
        return param
    except:
        print('获取最终参数失败（maybe错在第二步，maybe错在提取公式），位置：login_third')

def login_in(param):
    try:
        login_url = 'https://weibo.com/{}'.format(param)
        response = session.get(login_url,headers={'User-Agent':ua})
        session.cookies.save()
        print(response.content.decode('utf-8'))
    except BaseException as e:
        print(e)


if __name__ == "__main__":
    login_in(login_third(login_second(login_start(rsa_encryption(get_param())))))
