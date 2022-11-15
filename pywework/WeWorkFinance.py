# -*- coding=utf-8
import base64
import ctypes
import json
import os
import hashlib
import filetype
import tempfile
import io

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

class WeWorkFinance:
    '''
    企业微信的SDK命名为Finance，所以我也这么命名了
    '''
    def __init__(self, corpId:str, chatSecret:str, privateKey:str='') -> None:
        cw = os.path.dirname(__file__)
        path = os.path.abspath(cw)
        self.so = ctypes.cdll.LoadLibrary(f'{path}/libWeWorkFinanceSdk_C.so')
        self.so.GetContentFromSlice.restype = ctypes.c_char_p
        self.so.GetOutIndexBuf.restype = ctypes.c_char_p

        self.so.GetIndexLen.restype = ctypes.c_int
        self.so.GetDataLen.restype = ctypes.c_int
        self.so.IsMediaDataFinish.restype = ctypes.c_int
        self.sdk = self.so.NewSdk()
        errcode = self.so.Init(self.sdk, corpId.encode(), chatSecret.encode())
        if errcode != 0: #初始化失败
            exit(errcode)

        self.privateKey = privateKey #lazy loading
    
    def __del__(self):
        if self.so and self.sdk:
            self.so.DestroySdk(self.sdk)

    def getChatData(self, seq:int=0, limit:int=1000, options={}):
        slice = self.so.NewSlice()
        #d是一个状态值判断，0标识成功，函数参数/返回/处理内容看企业微信文档
        errcode = self.so.GetChatData(
            self.sdk, seq, limit, 
            options.get('proxy', ''), 
            options.get('passwd', ''), 
            options.get('timeout', 10), 
            ctypes.c_long(slice))
        if errcode != 0:
            return (errcode, [])
        rawData = self.so.GetContentFromSlice(slice)
        rawData = rawData.decode("utf-8")
        self.so.FreeSlice(slice)
        jsonData = json.loads(rawData)
        if jsonData['errcode'] != 0:
            return (jsonData['errcode'], [])
        chatData = jsonData['chatdata']
        if not options.get('decrypt', True):
            return (0, chatData)
        
        result = []
        if os.path.isfile(self.privateKey):
            with open(self.privateKey, 'r') as f:
                self.privateKey = f.read()
        
        pk = RSA.importKey(self.privateKey)
        cipher = PKCS1_v1_5.new(pk)

        for message in chatData:
            # #根据上面的密文解密明文，函数参数/返回/处理内容看企业微信文档
            # publickey_ver = message.get('publickey_ver') 暂时忽略版本对应关系
            randomKey = cipher.decrypt(base64.b64decode(message.get('encrypt_random_key')), "ERROR")
            if not randomKey:
                continue
            
            slices = self.so.NewSlice()
            self.so.DecryptData(randomKey, message.get('encrypt_chat_msg').encode(), ctypes.c_long(slices))
            data = self.so.GetContentFromSlice(slices)
            data = data.decode("utf-8")
            self.so.FreeSlice(slices)

            data = json.loads(data)
            message['decrypt_chat_msg'] = data
            del message['encrypt_random_key']
            del message['encrypt_chat_msg']
            result.append(message)
        return (0, result)
    
    def getMediaFile(self, fileId, dir: str, options: dict={}):
        '''
        return tuple(errcode, filepath, md5sum)
        '''
        fp = tempfile.NamedTemporaryFile(dir=dir, delete=False)
        indexbuf = ""
        with io.open(fp.name, 'wb+') as file:
            md5 = hashlib.md5()
            while True:
                mediaData = self.so.NewMediaData()
                errcode = self.so.GetMediaData(
                    self.sdk, indexbuf, fileId.encode(), 
                    options.get('proxy', ''), 
                    options.get('passwd', ''), 
                    options.get('timeout', 10), 
                    ctypes.c_long(mediaData))

                if errcode != 0:
                    self.so.FreeMediaData(mediaData)
                    return (errcode, '', '')
                dataLen = self.so.GetDataLen(mediaData)
                pdata = self.so.GetData(mediaData)
                data = ctypes.string_at(pdata, dataLen) #不要用-1，防止数据被截断
                md5.update(data)
                file.write(data)
                indexbuf = self.so.GetOutIndexBuf(ctypes.c_long(mediaData))
                self.so.FreeMediaData(ctypes.c_long(mediaData))
                if self.so.IsMediaDataFinish(mediaData):
                    break
        return (0, fp.name, md5.hexdigest())

__all__ = [
    'WeWorkFinance'
]

    



    
