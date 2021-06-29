import requests
import time
import logging
from datetime import datetime
import _thread
import os
import sys
import configparser
import string
from cryptography.fernet import Fernet
import platform
from requests.api import request
import torrequest
import enchant
import re
import random
import pyttsx3
from builtins import print
from bs4 import BeautifulSoup
from console.printers import print
version = '1.0.18b'
localsystem = platform.system()
if localsystem == 'Windows':
    import pythoncom
logfile = 'chat.log'

class _TTS:
    engine = None
    rate = None

    def __init__(self):
        if localsystem == 'Windows':
            pythoncom.CoInitializeEx(0)
        self.engine = pyttsx3.init()
        self.engine.setProperty('voice', 'russian')

    def start(self, text_):
        self.engine.say(text_)
        self.engine.runAndWait()

class _Request:
    tor = None

    def __init__(self):
        self.tor = torrequest.TorRequest(proxy_port=7050, ctrl_port=7051, password=None)

    def post(self, url, headers, json, data):
        res = self.tor.post(url, headers, json, data)
        self.tor.close()
        return res

class conchat:

    def __init__(self):
        self.renew()

    def myprint(self, text):
        print(text)

    def renew(self):
        print("""
╭━━━╮╱╱╱╱╱╱╱╱╭╮╱╱╱╱╭╮
┃╭━╮┃╱╱╱╱╱╱╱╱┃┃╱╱╱╭╯╰╮
┃┃╱╰╋━━┳━╮╭━━┫╰━┳━┻╮╭╯
┃┃╱╭┫╭╮┃╭╮┫╭━┫╭╮┃╭╮┃┃
┃╰━╯┃╰╯┃┃┃┃╰━┫┃┃┃╭╮┃╰╮
╰━━━┻━━┻╯╰┻━━┻╯╰┻╯╰┻━╯
""")
        print('conchat - ' + localsystem + ' ver.' + version)
        self.conf = configparser.ConfigParser()
        self.conf.read('chat.ini')
        self.uid = self.conf['chat']['uid']
        self.sid = self.conf['chat']['sid']
        self.name = self.conf['chat']['name']
        self.session = self.conf['chat']['session']
        self.csrf_token = self.conf['chat']['csrf_token']
        self.useTor = int(self.conf['chat']['useTor'])
        self.spellCheck = int(self.conf['chat']['spellCheck'])
        self.logfile = self.conf['chat']['logFile']
        self.useLog = int(self.conf['chat']['log'])
        self.logOnlyMode = int(self.conf['chat']['logOnlyMode'])
        self.subLepra = self.conf['chat']['subLepra']
        self.say = int(self.conf['chat']['say'])
        if self.subLepra != '':
            self.subLepra = str(self.subLepra) + '.'
        print('https://' + str(self.subLepra) + 'leprosorium.ru/')
        self.encr = False
        self.pauseChat = False
        if 'plaintext' in self.conf['chat']:
            self.plaintext = int(self.conf['chat']['plaintext'])
        else:
            self.plaintext = 0
        if 'yinfo' in self.conf['chat']:
            self.yinfo = int(self.conf['chat']['yinfo'])
        else:
            self.yinfo = 0
        if 'ydownload' in self.conf['chat']:
            self.ydownload = int(self.conf['chat']['ydownload'])
        else:
            self.ydownload = 0
        if 'silent' in self.conf['chat']:
            self.silent = int(self.conf['chat']['silent'])
        else:
            self.silent = 0
        self.intervalGetMess = 11
        self.getUrl = 'https://' + str(self.subLepra) + 'leprosorium.ru/ajax/chat/load/'
        self.addUrl = 'https://' + str(self.subLepra) + 'leprosorium.ru/ajax/chat/add/'
        self.apiUrl = 'https://leprosorium.ru/api/'
        self.headers = {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate, br', 'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8', 'Connection': 'keep-alive', 'Content-Length': '0', 'Host': str(self.subLepra) + 'leprosorium.ru', 'Origin': 'https://' + str(self.subLepra) + 'leprosorium.ru', 'Referer': 'https://' + str(self.subLepra) + 'leprosorium.ru/', 'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-origin', 'Cookie': 'wikilepro_session=' + self.session + '; uid=' + self.uid + '; sid=' + self.sid, 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36'}
        self.form = {'last_message_id': lm, 'csrf_token': self.csrf_token}
        self.Red = 31
        self.Green = 32
        self.Yellow = 33
        self.Blue = 34
        self.Purple = 35
        self.tor = None
        self.myprint('команды приложения:')
        self.myprint('#spel - проверка правописания, левописания')
        self.myprint('#lepra - указать подлепру')
        self.myprint('#exit - выход')
        self.myprint('#enc - шифрование сообщения общим ключом')
        self.myprint('ENTER - пауза вывода сообщений')
        self.myprint('#say - читать сообщения в слух')
        self.myprint('#plaintext - текстовый формат консоли')
        self.myprint('#tor - использование тора')
        self.myprint('#yinfo - информация о youtube ссылах')
        self.myprint('#ydownload - скачиавание youtube ссылок')
        self.myprint('#silent - не отсылать сообщения в чат')

    def get_logger(self, name):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.addHandler(self.log_handler)
        return logger

    def mess_loop(self, lm):
        while True:
            if self.pauseChat == True:
                time.sleep(2)
            lms = self.AddMessages(lm)
            if lms > lm:
                file = open('lastMessageNum.txt', 'w')
                file.write(str(lm) + '\n')
                lm = lms
            time.sleep(self.intervalGetMess)

    def sendMessage_loop(self):
        while True:
            try:
                msg = input()
                self.sendMessage(msg)
            except:
                self.exit_chat()

    def html_special_chars(self, text):
        return text.replace('&amp;', '&').replace('&quot;', '"').replace('&#039;', "'").replace('&lt;', '<').replace('&gt;', '>').replace('–', '-')

    def sendMessage(self, msg):
        send = True
        if '/python.exe' in msg:
            send = False
        if 'nyok' in msg:
            send = False
        if '#enc' in str(msg):
            key = self.load_key()
            f = Fernet(key)
            msg = str(f.encrypt(msg.encode()))
        if str(msg) == '':
            self.myprint('Вывод сообщений на паузе....пока ты набираешь текст.')
            self.pauseChat = True
            send = False
        if 'posts' in str(msg):
            if 'mixed' in str(msg):
                self.printPosts('mixed')
            elif 'main' in str(msg):
                self.printPosts('main')
            elif 'personal' in str(msg):
                self.printPosts('personal')
            else:
                self.myprint('Ошибка в выражении posts [mixed,main,personal]')
                self.myprint('posts mixed')
            send = False
        if '#spell' in str(msg):
            if self.spellCheck == 1:
                self.conf.set('chat', 'spellCheck', '0')
                self.spellCheck = 0
                self.myprint('spellCheck=0')
            else:
                self.conf.set('chat', 'spellCheck', '1')
                self.spellCheck = 1
                self.myprint('spellCheck=1')
            with open('chat.ini', 'w') as config_file:
                self.conf.write(config_file)
            send = False
        if '#lepra' in str(msg):
            self.subLepra = input('Подлепра:')
            self.conf.set('chat', 'subLepra', self.subLepra)
            with open('chat.ini', 'w') as config_file:
                self.conf.write(config_file)
            self.renew()
            send = False
        if '#say' in str(msg):
            if self.say == 1:
                self.myprint('say=0')
                self.conf.set('chat', 'say', '0')
                self.say = 0
            else:
                self.myprint('say=1')
                self.conf.set('chat', 'say', '1')
                self.say = 1
            with open('chat.ini', 'w') as config_file:
                self.conf.write(config_file)
            send = False
        if '#tor' in str(msg):
            if self.useTor == 1:
                self.myprint('useTor=0')
                self.conf.set('chat', 'useTor', '0')
                self.useTor = 0
            else:
                self.myprint('useTor=1')
                self.conf.set('chat', 'useTor', '1')
                self.useTor = 1
            with open('chat.ini', 'w') as config_file:
                self.conf.write(config_file)
            send = False
        if '#exit' in str(msg):
            self.exit_chat()
        if '#plaintext' in str(msg):
            if self.plaintext == 1:
                self.myprint('plaintext=0')
                self.conf.set('chat', 'plaintext', '0')
                self.plaintext = 0
            else:
                self.myprint('plaintext=1')
                self.conf.set('chat', 'plaintext', '1')
                self.plaintext = 1
            with open('chat.ini', 'w') as config_file:
                self.conf.write(config_file)
            send = False
        if '#yinfo' in str(msg):
            if self.yinfo == 1:
                self.myprint('yinfo=0')
                self.conf.set('chat', 'yinfo', '0')
                self.yinfo = 0
            else:
                self.myprint('yinfo=1')
                self.conf.set('chat', 'yinfo', '1')
                self.yinfo = 1
            with open('chat.ini', 'w') as config_file:
                self.conf.write(config_file)
            send = False
        if '#silent' in str(msg):
            if self.silent == 1:
                self.myprint('silent=0')
                self.conf.set('chat', 'silent', '0')
                self.silent = 0
            else:
                self.myprint('silent=1')
                self.conf.set('chat', 'silent', '1')
                self.silent = 1
            with open('chat.ini', 'w') as config_file:
                self.conf.write(config_file)
            send = False
        if '#ydownload' in str(msg):
            if self.ydownload == 1:
                self.myprint('ydownload=0')
                self.conf.set('chat', 'ydownload', '0')
                self.ydownload = 0
            else:
                self.myprint('ydownload=1')
                self.conf.set('chat', 'ydownload', '1')
                self.ydownload = 1
            with open('chat.ini', 'w') as config_file:
                self.conf.write(config_file)
            send = False
        if self.spellCheck == 1:
            c = enchant.Dict('ru_RU')
            msg = str(msg)
            for word in re.findall('[А-Яа-я]+', str(msg)):
                if c.check(word) == False:
                    lst = c.suggest(word)
                    if len(lst) > 0:
                        sugid = random.randint(0, len(lst) - 1)
                        wrd = lst[sugid]
                        msg = msg.replace(word, wrd, 1)
        if self.silent == 1:
            send = False
        if send == True:
            form2 = {'last': lm, 'csrf_token': self.csrf_token, 'body': msg}
            tc = self.req()
            tc.post(self.addUrl, headers=self.headers, json=form2, data=form2)
            self.pauseChat = False

    def req(self):
        if self.useTor == 1:
            if localsystem == 'Linux':
                rq = _Request()
            else:
                rq = torrequest.TorRequest(proxy_port=7050, ctrl_port=7051, password=None)
            return rq
        r = requests
        return r

    def getMessages(self):
        try:
            tc = self.req()
            r = tc.post(self.getUrl, headers=self.headers, json=self.form, data=self.form)
            return r.json()
        except Exception:
            self.myprint('чёта с инетом... \n ')
            time.sleep(5)
            return

    def l(self, text):
        self.log.info(text)

    def getposts(self, feed_type):
        url = self.apiUrl + 'feeds/' + feed_type + '/'
        tc = self.req()
        r = tc.get(url, headers={'X-Futuware-UID': self.uid, 'X-Futuware-SID': self.id})
        result = r.json()
        return result

    def printPosts(self, feed_type):
        posts = self.getposts(feed_type)
        for post in posts['posts']:
            link = str('\x1b[1;' + str(self.Yellow) + ';40m' + post['_links'][0]['href'] + '\x1b[0m ')
            rating = str('\x1b[1;' + str(self.Red) + ';40m' + str(post['rating']) + '\x1b[0m ')
            login = str('\x1b[1;' + str(self.Green) + ';40m' + str(post['user']['login']) + '\x1b[0m ')
            id = str('\x1b[1;' + str(self.Purple) + ';40m' + str(post['id']) + '\x1b[0m ')
            comments_count = str('\x1b[1;' + str(Blue) + ';40m' + str(post['comments_count']) + '\x1b[0m ')
            created = datetime.fromtimestamp(post['created'])
            today = datetime.today()
            d1 = today.strftime('%m/%Y')
            d2 = created.strftime('%m/%Y')
            if not d1 == d2:
                continue
        self.myprint('л, ' + link + ' р, ' + rating + ' %, ' + login + ' д, ' + created.strftime('%Y-%m-%d-%H.%M') + ' к,' + comments_count + ' id:' + id)
        self.myprint(post['body'])

    def load_key(self):
        '''
        Loads the key from the current directory named `key.key`
        '''
        defaultKey = b'jkE4yxD4azCxKL3_R1-kRy6RbZGf0pwxJGAZOtiPg8E='
        return defaultKey

    def ClearLog(self):
        try:
            if not os.path.isfile(self.logfile):
                return
            if os.path.isfile(self.logfile + '.old'):
                os.remove(self.logfile + '.old')
            os.rename(self.logfile, self.logfile + '.old')
            lines_seen = set()
            outfile = open(self.logfile, 'w')
            for line in open(self.logfile + '.old', 'r'):
                if line not in lines_seen:
                    outfile.write(line)
                    lines_seen.add(line)
            outfile.close()
        except:
            pass

    def InfoYoutube(self, url):
        try:
            res = pafy.new(url)
            print(f'Title: {res.title}')
            print(f'Viewcount {res.viewcount}')
            print(f'Author: {res.author}')
            print(f'Video Length: {res.length}')
            print(f'Likes: {res.likes}')
            print(f'Dislikes: {res.dislikes}')
            print(f'Description: {res.description}')
            if 'Artist' in res:
                print(f'Artist: {res.artist}')
            if 'Artist' in res:
                print(f'Song: {res.song}')
        except:
            pass
        return {'title': f'{res.title}', 'length': f'{res.length}'}

    def DownloadYoutube(self, url):
        result = pafy.new(url)
        best_quality_audio = result.getbestaudio()
        print('Начинаю загрузку аудио ....')
        best_quality_audio.download()

    def AddMessages(self, lm):
        if self.pauseChat == True:
            return lm
        result = self.getMessages()
        if result == None:
            return lm
        if 'messages' in result:
            mess = result['messages']
        else:
            mess = []
            self.myprint('Ошибка, возможно узел закрыт или Вас забанили...')
            return lm
        id = 0
        for message in mess:
            id = message['id']
            if int(id) <= int(lm):
                continue
            login = str(message['user']['login'])
            messageText = str(message['body'])
            messageText = self.html_special_chars(messageText)
            created = datetime.fromtimestamp(message['created'])
            if "b'" in str(messageText):
                if ' ' not in str(messageText):
                    messageText = messageText.replace("b'", '').replace("'", '')
                    try:
                        self.myprint('Расшифровка - ' + messageText)
                        key = self.load_key()
                        f = Fernet(key.decode())
                        messageText = str(f.decrypt(messageText.encode()).decode())
                    except:
                        self.myprint('ХХХХ')
            elif self.say == 1:
                tts = _TTS()
                tts.start(messageText)
                del tts
            if self.plaintext == 1 and '<' in messageText and '>' in messageText:
                soup = BeautifulSoup(messageText, features='lxml')
                messageText = soup.getText()
            messageText = self.html_special_chars(messageText)
            urls = re.findall('((https?):((//)|(\\\\))+([\\w\\d:#@%/;$()~_?\\+-=\\\\.&](#!)?)*)', messageText)
            for url in urls:
                if 'youtube.com' or 'youtu.be' in url[0]:
                    title = ''
                    if self.yinfo == 1:
                        try:
                            rs = self.InfoYoutube(url[0])
                            title = rs['title']
                        except:
                            pass
                    if self.ydownload == 1 and title != '' and int(rs['length']) < 500:
                        try:
                            if not os.path.isfile(title + '.webm') and not (not os.path.isfile(title + '.m4a') and not os.path.isfile(title + '.mp3')):
                                _thread.start_new_thread(self.DownloadYoutube, (url[0],))
                        except:
                            pass
            if login != self.name and self.name in messageText:
                tts = _TTS()
                tts.start(messageText)
            log_msg = str(created.strftime('%m-%d-%H.%M') + '|' + login + '|' + messageText + '|' + str(id) + '|' + str(message['created']))
            mynick = str('\x1b[1;' + str(self.Red) + ';40m' + self.name + ':\x1b[0m ')
            messageText = messageText.replace(self.name, mynick)
            if login != self.name:
                msg = str('\x1b[1;' + str(self.Yellow) + ';40m' + created.strftime('%H.%M') + ':\x1b[0m ' + '\x1b[1;' + str(self.Green) + ';40m' + login + ':\x1b[0m ' + messageText)
            else:
                msg = str('\x1b[1;' + str(self.Yellow) + ';40m' + created.strftime('%H.%M') + ':\x1b[0m ' + '\x1b[1;' + str(self.Red) + ';40m' + login + ':\x1b[0m ' + messageText)
            self.myprint(msg)
            log_msg = str(log_msg)
            if self.useLog == 1:
                self.l(log_msg)
        return id

    def exit_chat(self):
        try:
            print('conchat ' + version)
            print('by')
            print("""
─╔╗───╔╦╗
─║╠╦╦═╬╣╚╦═╦╦╗
╔╣║║║╬║║╔╣╩╣╔╝
╚═╩═╣╔╩╩═╩═╩╝
────╚╝""")
            handlers = self.log.handlers.copy()
            for handler in handlers:
                try:
                    handler.acquire()
                    handler.flush()
                    handler.close()
                except (OSError, ValueError):
                    pass
                finally:
                    handler.release()
                self.log.removeHandler(handler)
            sys.exit(0)
        except SystemExit:
            os._exit(0)

    def startChat(self, lm, log_handler):
        self.log_handler = log_handler
        self.log = self.get_logger(__name__)
        try:
            _thread.start_new_thread(self.mess_loop, (lm,))
        except:
            self.myprint('Ошибка в потоке сообщений,  закрытие приложения')
        try:
            _thread.start_new_thread(self.sendMessage_loop, ())
        except:
            self.myprint('Ошибка в потоке отправки, выход....')
        while True:
            time.sleep(1)

def write_key():
    '''
    Generates a key and save it into a file
    '''
    key = Fernet.generate_key()
    with open('key.key', 'wb') as key_file:
        key_file.write(key)

def load_key():
    '''
    Loads the key from the current directory named `key.key`
    '''
    defaultKey = 'jkE4yxD4azCxKL3_R1-kRy6RbZGf0pwxJGAZOtiPg8E='
    return defaultKey

def loginLzd(uname, pas):
    lurl = 'https://leprosorium.ru/ajax/auth/login/ '
    hdlg = {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate, br', 'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8', 'Connection': 'keep-alive', 'Content-Length': '0', 'Host': 'leprosorium.ru', 'Referer': 'https://leprosorium.ru/login/', 'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-origin', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36'}
    formlg = {'username': uname, 'password': pas, 'g-recaptcha-response': ''}
    r = requests.post(lurl, headers=hdlg, json=formlg, data=formlg)
    d = r.json()
    if d['status'] == 'OK':
        config = configparser.ConfigParser()
        config.add_section('chat')
        config.set('chat', 'uid', r.cookies['uid'])
        config.set('chat', 'sid', r.cookies['sid'])
        config.set('chat', 'session', '')
        config.set('chat', 'csrf_token', d['csrf_token'])
        config.set('chat', 'logFile', 'chat.log')
        config.set('chat', 'spellCheck', '0')
        config.set('chat', 'log', '1')
        config.set('chat', 'name', uname)
        config.set('chat', 'useTor', '0')
        config.set('chat', 'logOnlyMode', '0')
        config.set('chat', 'subLepra', '')
        config.set('chat', 'say', '0')
        config.set('chat', 'yinfo', '0')
        config.set('chat', 'ydownload', '0')
        with open('chat.ini', 'w') as config_file:
            config.write(config_file)
            return True
    return False

def exit_chat():
    try:
        sys.exit(0)
    except SystemExit:
        os._exit(0)

def setup():
    print('отсутствует chat.ini')
    print("""Зайти через логин / пароль?
""")
    answer = input('Yes|No\n')
    if answer == 'Yes':
        log = input('login:')
        pas = input('password:')
        if loginLzd(log, pas) == True:
            print('Записано на будущеее... ')
        else:
            print('нету chat.ini\n')
            exit_chat()

def get_file_handler():
    _log_format = '%(message)s'
    today = datetime.today()
    file_handler = logging.FileHandler(logfile + '.' + today.strftime('%y%m%d%H%M') + '.log', 'w', 'utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(_log_format))
    return file_handler

if __name__ == '__main__':
    tx = """conchat
    Скачать новую версию:
    https://gofile.io/d/KheQAd
    """
    print(tx)
    lm = 1400000
    log_handler = get_file_handler()
    if not os.path.isfile('chat.ini'):
        setup()
    try:
        file = open('lastMessageNum.txt', 'r+')
        write = False
    except:
        file = open('lastMessageNum.txt', 'w')
        write = True
    try:
        if not write:
            lines = file.readlines()
            lm = int(lines[0][:-1]) - 50
    except:
        print('Ошибка чтения последнего сообщения...ничего страшного, просто для информации')
        lm = 1
    chat = conchat()
    try:
        chat.startChat(lm, log_handler)
    except KeyboardInterrupt:
        print('   выход из приложения ctl+c  KeyboardInterrupt')
        exit_chat()
