#!/usr/bin/env python
# -*- coding: utf-8 -*-
from RSA import _key
from tkinter import *
import hashlib
import re
import time
from Liu import *
from RSA import *
LOG_LINE_NUM = 0

class MY_GUI():
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name


    #设置窗口
    def set_init_window(self):
        self.init_window_name.title("文本处理工具_v1.2")           #窗口名
        # self.init_window_name.geometry('320x160+10+10')                         #290 160为窗口大小，+10 +10 定义窗口弹出时的默认展示位置
        self.init_window_name.geometry('1024x581+10+10')
        self.init_window_name["bg"] = "lightblue"                                    #窗口背景色，其他背景色见：blog.csdn.net/chl0000/article/details/7657887
        # self.init_window_name.attributes("-alpha",0.9)                          #虚化，值越小虚化程度越高
        #标签
        self.init_data_label = Label(self.init_window_name, text="待处理数据")
        self.init_data_label.grid(row=0, column=0)
        self.result_data_label = Label(self.init_window_name, text="输出结果")
        self.result_data_label.grid(row=0, column=12)
        self.log_label = Label(self.init_window_name, text="日志")
        self.log_label.grid(row=12, column=0)
        #! 因为RC4 和LFSR都是一个密钥------>所以我直接写一个窗口
        self.key_value_lable = Label(self.init_window_name,text="密钥：",bg="red")
        self.key_value_lable.grid(row=12,column=12)
        #文本框
        self.init_data_Text = Text(self.init_window_name, width=67, height=20)  #原始数据录入框
        self.init_data_Text.grid(row=1, column=0, rowspan=10, columnspan=10)
        self.result_data_Text = Text(self.init_window_name, width=45, height=20)  #处理结果展示
        self.result_data_Text.grid(row=1, column=12, rowspan=10, columnspan=5)
        self.log_data_Text = Text(self.init_window_name, width=50, height=15)  # 日志框
        self.log_data_Text.grid(row=13, column=0, columnspan=10)
        #! rc4
        self.key_Text = Text(self.init_window_name,width=50,height=1)
        self.key_Text.grid(row = 12,column= 13)

        #按钮

        #! 解密

        """
        self.rc4_buttion = Button(self.init_window_name, text="RC4算法", bg="green", width=10,
                                  command=self.str_trans_RC4)  # ! 调用内部方法直接调用
        # self.rc4_buttion.grid(row=1,column=11)
        self.rc4_buttion.place(x=473, y=25)
        # ! 解密
        self.rc4_buttion_slove = Button(self.init_window_name, text="RC4解密", bg="lightblue", width=10,
                                        command=self.RC4_trans_str)
        self.rc4_buttion_slove.place(x=473, y=53)

        self.lfsr_buttion = Button(self.init_window_name, text="LFSR算法", bg="yellow", width=10,
                                   command=self.str_trans_LFSR)  # ! 调用内部方法直接调用
        self.lfsr_buttion.grid(row=3, column=11)

        self.lfsr_buttion_slove = Button(self.init_window_name, text="LFSR解密", bg="Turquoise", width=10,
                                         command=self.LFSR_to_str)
        self.lfsr_buttion_slove.place(x=473, y=110)
        """

        #RSA加密解密
        self.RSA_buttion = Button(self.init_window_name,text="RSA算法",bg="green",width=10,command=self.str_trans_RSA) #! 调用内部方法直接调用

        self.RSA_buttion.place(x = 473,y = 60)

        self.RSA_buttion_slove = Button(self.init_window_name,text="RSA解密",bg="lightblue",width=10,command=self.RSA_trans_str)
        self.RSA_buttion_slove.place(x = 473,y = 90)
        #密钥
    def LFSR_to_str(self):
        src = self.init_data_Text.get(1.0,END).strip().replace("\n","")#.encode()
        if src:
            try:
                test_byte_data = src
                seed_key = self.key_Text.get(1.0,END).strip().replace("\n","")
                if seed_key!="":
                    # print(seed_key)
                    # test_byte_data = input("请输入要加密的明文：")
                    k = seed_key
                    key = get_str_bits(k)
                    l = cypto_LFSR(key)
                    str_temp_lfsr_miwen = l.do_crypt(get_str_bits(test_byte_data))
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,str_temp_lfsr_miwen)
                    self.write_log_to_Text("INFO:str_trans_to_LFSR success")
                else:
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,"未输入seed_key")
            except:
                self.result_data_Text.delete(1.0,END)
                self.result_data_Text.insert(1.0,"密文转化失败")
        else:
             self.write_log_to_Text("ERROR:LFSR_trans_to_str failed")
    
    def RC4_trans_str(self):
        src = self.init_data_Text.get(1.0,END).strip().replace("\n","")#.encode()
        if src:
            try:
                test_byte_data = src
                seed_key = self.key_Text.get(1.0,END).strip().replace("\n","")
                if seed_key!="":
                    # print(seed_key)
                    encrpty_text = decrypt_str(test_byte_data, seed_key)
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,encrpty_text)
                    self.write_log_to_Text("INFO:str_trans_to_RC4 success")
                else:
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,"未输入seed_key")
            except:
                self.result_data_Text.delete(1.0,END)
                self.result_data_Text.insert(1.0,"密文转化失败")
        else:
            self.write_log_to_Text("ERROR:Rc4_trans_to_str failed")
    def str_trans_LFSR(self):
        src = self.init_data_Text.get(1.0,END).strip().replace("\n","")#.encode()
        if src:
            try:
                test_byte_data = src
                seed_key = self.key_Text.get(1.0,END).strip().replace("\n","")
                if seed_key!="":
                    # print(seed_key)
                    # test_byte_data = input("请输入要加密的明文：")
                    k = seed_key
                    key = get_str_bits(k)
                    l = cypto_LFSR(key)
                    str_temp_lfsr_miwen = l.do_crypt(get_str_bits(test_byte_data))
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,str_temp_lfsr_miwen)
                    self.write_log_to_Text("INFO:str_trans_to_LFSR success")
                else:
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,"未输入seed_key")
            except:
                self.result_data_Text.delete(1.0,END)
                self.result_data_Text.insert(1.0,"明文转化失败")
        else:
             self.write_log_to_Text("ERROR:str_trans_to_LFSR failed")
    
    def str_trans_RC4(self):
        src = self.init_data_Text.get(1.0,END).strip().replace("\n","")#.encode()
        if src:
            try:
                test_byte_data = src
                seed_key = self.key_Text.get(1.0,END).strip().replace("\n","")
                if seed_key!="":
                    print(seed_key)
                    encrpty_text = encrypt_str(test_byte_data, seed_key)
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,encrpty_text)
                    self.write_log_to_Text("INFO:str_trans_to_RC4 success")
                else:
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,"未输入seed_key")
            except:
                self.result_data_Text.delete(1.0,END)
                self.result_data_Text.insert(1.0,"明文转化失败")
        else:
             self.write_log_to_Text("ERROR:str_trans_to_RC4 failed")

    #功能函数
    def is_number(s):
        try:
            float(s)
            return True
        except ValueError:
            pass
        try:
            import unicodedata
            unicodedata.numeric(s)
            return True
        except (TypeError, ValueError):
            pass
        return False

    def str_trans_RSA(self):
        src = self.init_data_Text.get(1.0, END).strip().replace("\n", "")#.encode()
        # print("src =",src)
        if src:
            try:
                test_byte_data = src
                ecrypt_text = RSAecrypt(test_byte_data,_key)
                # print(myMd5_Digest)
                # 输出到界面
                self.result_data_Text.delete(1.0, END)
                self.result_data_Text.insert(1.0, ecrypt_text)
                self.key_Text.delete(1.0, END)
                self.key_Text.insert(1.0, "公钥：")
                self.key_Text.insert(5.0, _key.share_key)
                self.key_Text.insert(10.0, " ")
                self.key_Text.insert(15.0, _key.public_key)
                self.key_Text.insert(20.0, "  私钥：")
                self.key_Text.insert(25.0, _key.share_key)
                self.key_Text.insert(30.0, " ")
                self.key_Text.insert(35.0, _key.private_key)
                self.write_log_to_Text("INFO:str_trans_RSA success")
            except:
                self.result_data_Text.delete(1.0, END)
                self.result_data_Text.insert(1.0, "加密失败")
        else:
            self.write_log_to_Text("ERROR:str_trans_RSA failed")

    def RSA_trans_str(self):
        src = self.init_data_Text.get(1.0, END).strip().replace("\n", "")#.encode()
        if src:
            try:
                test_byte_data = src.split(' ')
                test_byte_data = [int(x) for x in test_byte_data]
                get_key = self.key_Text.get(1.0, END).strip().replace("\n", "")
                seed_key = _key
                str=get_key.split()
                _key.share_key=re.findall(r"\d+",str[0])
                _key.public_key=re.findall(r"\d+",str[1])
                _key.private_key=re.findall(r"\d+",str[3])
                seed_key=_key
                decrypt_text = RSAdecrypt(test_byte_data,seed_key)
                print(seed_key.share_key)
                # print(myMd5_Digest)
                # 输出到界面
                self.result_data_Text.delete(1.0, END)
                self.result_data_Text.insert(1.0, decrypt_text)
                self.write_log_to_Text("INFO:RSA_trans_str success")
            except:
                self.result_data_Text.delete(1.0, END)
                self.result_data_Text.insert(1.0, "解密失败")

        else:
            self.write_log_to_Text("ERROR:RSA_trans_str failed")


    #获取当前时间
    def get_current_time(self):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        return current_time


    #日志动态打印
    def write_log_to_Text(self,logmsg):
        global LOG_LINE_NUM
        current_time = self.get_current_time()
        logmsg_in = str(current_time) +" " + str(logmsg) + "\n"      #换行
        if LOG_LINE_NUM <= 7:
            self.log_data_Text.insert(END, logmsg_in)
            LOG_LINE_NUM = LOG_LINE_NUM + 1
        else:
            self.log_data_Text.delete(1.0,2.0)
            self.log_data_Text.insert(END, logmsg_in)


def gui_start():
    init_window = Tk()              #实例化出一个父窗口
    ZMJ_PORTAL = MY_GUI(init_window)
    # 设置根窗口默认属性
    ZMJ_PORTAL.set_init_window()

    init_window.mainloop()          #父窗口进入事件循环，可以理解为保持窗口运行，否则界面不展示


gui_start()