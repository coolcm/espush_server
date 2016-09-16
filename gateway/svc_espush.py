#!/usr/bin/env python
# encoding: utf-8

from __future__ import unicode_literals
from __future__ import print_function


import time
import socket
import struct
import base64
import urllib
import pprint
import hashlib
import weakref
import datetime
import argparse


from zope.interface import implements

from twisted.internet import protocol, reactor
from twisted.internet.defer import succeed, inlineCallbacks, Deferred
from twisted.protocols.policies import TimeoutMixin
from twisted.web.client import Agent
from twisted.web.iweb import IBodyProducer
from twisted.web.http_headers import Headers


from common import (write_pid_file, SvcConfig, JSONProtocol,
                    DeviceCls, timestamp, MultiDeviceFound, to_int,
                    DeviceOfflined, DeviceNotFound, JSONClientFactory,
                    DBopr, DeviceDisconnected, initlog, logger, our_ips)
import sys


class CONST(object):
    ''':summary: 协议无需硬编码'''
    MSG_DEVRP_REQ = 0x00
    MSG_DEVRP_RSP = 0x01
    MSG_HEART_REQ = 0x02
    MSG_HEART_RSP = 0x03
    MSG_PUSH_REQ = 0x04
    MSG_PUSH_RSP = 0x05
    MSG_UPLOAD_REQ = 0x06
    MSG_UPLOAD_RSP = 0x07
    MSG_LOGOFF_REQ = 0x08
    MSG_LOGOFF_RSP = 0x09
    MSG_UPDATE_PUSH_QUERY_REQ = 0x0A
    MSG_UPDATE_PUSH_QUERY_RSP = 0x0B
    MSG_UPDATE_PUSH_BIN_REQ = 0x0C
    MSG_UPDATE_PUSH_BIN_RSP = 0x0D
    MSG_UPDATE_PUSH_COMPLETE_REQ = 0x0E
    MSG_UPDATE_PUSH_COMPLETE_RSP = 0x0F
    MSG_FLASH_DUMP_REQ = 0x10
    MSG_FLASH_DUMP_RSP = 0x11
    MSG_REBOOT_REQ = 0x12
    MSG_REBOOT_RSP = 0x13
    MSG_CLOUD_ATCMD_REQ = 0x14
    MSG_CLOUD_ATCMD_RSP = 0x15
    MSG_CLOUD_LUAFILE_REQ = 0x16
    MSG_CLOUD_LUAFILE_RSP = 0x17
    MSG_SERVER_HEARTBEAT_REQ = 0x18
    MSG_SERVER_HEARTBEAT_RSP = 0x19
    MSG_CLOUD_CONSOLE_BEGIN_REQ = 0x1A
    MSG_CLOUD_CONSOLE_BEGIN_RSP = 0x1B
    MSG_RT_STATUS_REQ = 0x1C
    MSG_RT_STATUS_RSP = 0x1D
    MSG_GPIO_OPR_REQ = 0x1E
    MSG_GPIO_OPR_RSP = 0x1F
    MSG_GPIO_STATUS_REQ = 0x20
    MSG_GPIO_STATUS_RSP = 0x21
    MSG_UART_TRANS_STREAM_REQ = 0x22
    MSG_UART_TRANS_STREAM_RSP = 0x23
    MSG_SINGLE_DEV_INIT_REQ = 0x24
    MSG_SINGLE_DEV_INIT_RSP = 0x25
    MSG_CUSTOM_MSGTYPE_REQ = 0x26
    MSG_CUSTOM_MSGTYPE_RSP = 0x27
    MSG_SWITCH_SERVER_REQ = 0x28
    MSG_SWITCH_SERVER_RSP = 0x29


def md5(body):
    '''
    :summary: 便捷的md5操作，单独的md5 模块已被标记为废除了
    '''
    return hashlib.md5(body).hexdigest()


def calculate_sign_str(method, params, appkey):
    '''
    :summary: 计算sign值
    :param method: POST
    :param params: {}
    :param appkey: appkey
    '''
    stra = method.lower()
    keys = params.keys()
    keys.sort()
    keys.reverse()
    strb = '&'.join(['%s=%s'.lower() % (el, params[el]) for el in keys])
    strc = appkey.lower()
    return md5(stra + strb + strc)


class EspushDevice(DeviceCls):
    def __init__(self, **kwargs):
        DeviceCls.__init__(self, **kwargs)
        assert('protocol_ref' in kwargs)
        self.latest_confirm = timestamp()
        ': :type self.protocol: ServerProtocol'
        self.protocol_ref = kwargs['protocol_ref']
        assert('conn_hash' in kwargs)
        self.conn_hash = kwargs['conn_hash']

    def heartbeat(self, timestamp):
        self.latest_confirm = timestamp


class ProtocolProcess(object):
    '''连接具体的业务处理class

    / 按具体的应用协议划分函数
    00 设备初始化  01 设备初始化返回
    02 心跳协议请求  03 心跳协议返回
    04 数据推送请求 05 数据推送返回
    06 数据上传请求 07 数据上传返回
    08 注销请求           09 注销返回
    / 更多协议请参考协议文档
    '''

    def __init__(self, proto_ref):
        self.deferreds = []
        self.protocol_ref = proto_ref
        self.conn_hash = id(self.protocol_ref())

    @staticmethod
    def msgid_from_frame(frame):
        msgid, = struct.unpack(b'!I', frame[4: 8])
        return msgid

    @staticmethod
    def cbResponse(msg):
        logger.info('接口调用成功 %r', msg)

    @staticmethod
    def cbShutdown(_):
        logger.info('接口调用完成')

    def msg_websocket_notice(self, msg, chipid):
        params = {
            'appid': self.app_id,
            'timestamp': str(int(time.time())),
            'chipid': chipid,
            'type': 'data_upload',
        }
        self.web_notice(msg, params)

    @inlineCallbacks
    def msg_notice_api_call(self, msg):
        agent = Agent(reactor)

        notice_result = yield gl_dbopr.get_notice_from_appid(self.app_id)
        if not notice_result:
            logger.warn('设备未配置回调接口 [%d]', self.chip_id)
            return
        addr, token = notice_result[0]
        if not addr or not token:
            logger.warn('接口地址或token值为空 [%d]', self.chip_id)
            return

        params = {
            'appid': self.app_id,
            'timestamp': str(int(time.time())),
            'token': token
        }
        sign_str = calculate_sign_str('POST', params, self.app_key)
        params['sign'] = sign_str
        url = '%s?%s' % (addr, urllib.urlencode(params))
        url = url.encode('utf-8')
        logger.info('请求远程接口地址URL [%s]', url)

        class StringProducer(object):
            '''
            :summary: twisted 对post请求要求使用IBodyProducer接口
            // twisted 的 web client对unicode似乎敏感，所有与之相关的地方都只能使用byte
            '''
            implements(IBodyProducer)

            def __init__(self, body):
                self.body = body
                self.length = len(body)

            def startProducing(self, consumer):
                consumer.write(self.body)
                return succeed(None)

        if isinstance(msg, unicode):
            msg = msg.encode('utf-8')
        body = StringProducer(base64.b64encode(msg))
        defered = agent.request(b'POST', url,
                                Headers({b'User-Agent':
                                         [b'espush WebAPI Client v0.1']}),
                                body)
        defered.addCallback(self.cbResponse)
        defered.addBoth(self.cbShutdown)

    @inlineCallbacks
    def exec_00(self):
        '''解析设备报告指令

        / 设备报告协议分为两个不同的版本，新的版本同时汇报 flash_map, vertype
        / 即Flash容量、固件类型，启动类型，启动APP等
        / 但之前发行的固件启动时并未汇报这些信息，故在此做了想下兼容处理
        '''
        self.app_id, = struct.unpack(b'!I', self.frame[10: 10 + 4])
        self.app_key = self.frame[14: 14 + 32]
        self.chip_id, = struct.unpack(b'!I', self.frame[46: 46 + 4])
        if len(self.frame) > 50:
            (self.devkey, self.vertype, self.flashmap, self.second_boot,
                self.boot_app) = struct.unpack(b'!32sBBBB', self.frame[50:])
        else:
            (self.devkey, self.vertype, self.flashmap, self.second_boot,
                self.boot_app) = (0, 0, 0, 0, 0)
        apps_res = yield gl_dbopr.apps_from_appid_and_key(self.app_id,
                                                          self.app_key)
        fmt = b'!IIHB'
        length = struct.calcsize(fmt)
        msgid = self.msgid_from_frame(self.frame)
        if not apps_res:
            logger.warn('未知设备 [%d, %s], DEV: [%d]',
                        self.app_id, self.app_key, self.chip_id)
            body = struct.pack(fmt, length, msgid, CONST.MSG_DEVRP_RSP, 1)
            self.proto_inst().transport.write(body)
            self.proto_inst().transport.loseConnection()
            return
        self.proto_inst().factory.add_dev(self.app_id, self.app_key,
                                          self.chip_id,
                                          protocol_ref=self.protocol_ref,
                                          devkey=self.devkey,
                                          vertype=self.vertype,
                                          conn_hash=self.conn_hash)
        self.device_tbl_id = yield gl_dbopr.chip_to_db(self.chip_id,
                                                       self.app_id)
        logger.info('设备初始化请求已收到 APP:[%d, %s], DEV:[%d]',
                    self.app_id, self.app_key, self.chip_id)
        body = struct.pack(fmt, length, msgid, CONST.MSG_DEVRP_RSP, 0)
        self.proto_inst().transport.write(body)

    def exec_02(self):
        assert self.app_id and self.chip_id
        assert len(self.frame) == 10
        logger.info('[%d] 设备心跳请求, 进程内有设备数: [%d]',
                    self.chip_id, len(client_factory._devices))
        timestamp = int(time.time())
        # 总长10， 类型3
        fmt = b'!IIHI'
        length = struct.calcsize(fmt)
        body = struct.pack(fmt, length, self.msgid,
                           CONST.MSG_HEART_RSP, timestamp)
        self.proto_inst().transport.write(body)
        self.proto_inst().factory.dev_confirm(self.chip_id)

    @inlineCallbacks
    def exec_06(self):
        logger.info('[%d] 数据上传', self.chip_id)
        assert self.app_key and self.app_id and self.chip_id, '设备未注册'
        _, msg_id, _, _, timestamp = struct.unpack(b'!IIHHI', self.frame[:16])
        content = self.frame[16:]
        msg_body = content.strip()
        # 换个地方保存
        if msg_body.find(',') == -1:
            tag = ''
            body = msg_body
        else:
            tag = msg_body.split(',')[0]
            body = ''.join(msg_body.split(',')[1:])
        rec_obj = {
            'device_tbl_id': self.device_tbl_id,
            'app_id': self.app_id,
            'tag': tag,
            'create_time': datetime.datetime.fromtimestamp(timestamp),
            'recv_time': datetime.datetime.now(),
            'body': body
        }
        yield gl_dbopr.upload_msg_save(rec_obj)
        fmt = b'!IIHB'
        length = struct.calcsize(fmt)
        body = struct.pack(fmt, length, msg_id, CONST.MSG_UPLOAD_RSP, 0)
        self.proto_inst().transport.write(body)
        # self.msg_notice_api_call(content)
        self.msg_websocket_notice(content, self.chip_id)

    def proto_inst(self):
        protocol_inst = self.protocol_ref()
        if protocol_inst is None:
            msg = '[%d] 连接REF为空, 已断开' % self.chip_id
            logger.warn(msg)
            raise DeviceDisconnected(msg)
        return protocol_inst

    def exec_05(self):
        '''数据返回处理函数

        / 大部分的此类exec_ ，针对设备返回的，多不需要关注
        / 只需要手动调用self.api_retval即可自动处理
        '''
        self.api_retval()
        logger.info('[%d] 数据返回报告', self.chip_id)

    def exec_08(self):
        self.api_retval()
        logger.info('[%d] 设备注销请求', self.chip_id)

    def exec_0B(self):
        self.api_retval()
        logger.info('[%d] 设备升级QUERY返回: %s', self.chip_id, repr(self.frame))

    def exec_0D(self):
        self.api_retval()
        logger.info('[%d] 设备升级数据推送返回 %s', self.chip_id, repr(self.frame))

    def exec_0F(self):
        self.api_retval()
        logger.info('[%d] 设备升级完成 指令返回 %s', self.chip_id, repr(self.frame))

    def exec_11(self):
        self.api_retval()
        logger.info('[%d] dump flash returned', self.chip_id)

    def exec_19(self):
        self.api_retval()
        logger.info('[%d] 主动心跳探知', self.chip_id)

    def exec_15(self):
        self.api_retval()
        logger.info('[%d] AT指令收到返回', self.chip_id)

    def exec_17(self):
        self.api_retval()
        logger.info('[%d] Lua返回', self.chip_id)

    def exec_13(self):
        self.api_retval()
        logger.info('[%d] 重启收到返回', self.chip_id)

    def web_notice(self, msg, params):
        '''
        :summary: 跨进程通知
        :param msg:
        :param params:
        '''
        class StringProducer(object):
            '''
            :summary: twisted 对post请求要求使用IBodyProducer接口
            '''
            implements(IBodyProducer)

            def __init__(self, body):
                self.body = body
                self.length = len(body)

            def startProducing(self, consumer):
                consumer.write(self.body)
                return succeed(None)

        agent = Agent(reactor)
        url = '%s?%s' % ('http://localhost:9999/noticed/recv',
                         urllib.urlencode(params))
        url = url.encode('utf-8')
        logger.info('[%d] 请求websocket接口地址URL [%s]', self.chip_id, url)
        if isinstance(msg, unicode):
            msg = msg.encode('utf-8')
        body = StringProducer(base64.b64encode(msg))
        defered = agent.request(b'POST', url,
                                Headers({b'User-Agent':
                                         [b'espush WebAPI Client v0.1']}),
                                body)
        defered.addCallback(self.cbResponse)
        defered.addBoth(self.cbShutdown)
        return defered

    def exec_22(self):
        logger.info('[%d] 串口透传 字符流请求', self.chip_id)
        params = {
            'appid': self.app_id,
            'timestamp': str(int(time.time())),
            'chipid': self.chip_id,
            'type': 'uart_trans',
        }
        msg = self.frame[10:]
        cur_msgid = self.msgid_from_frame(self.frame)
        self.web_notice(msg, params)
        fmt = b'!IIHB'
        length = struct.calcsize(fmt)
        body = struct.pack(fmt, length, cur_msgid,
                           CONST.MSG_UART_TRANS_STREAM_RSP, 0)
        self.proto_inst().transport.write(body)

    @inlineCallbacks
    def exec_24(self):
        msg_id = self.msgid_from_frame(self.frame)
        self.chip_id, = struct.unpack(b'!I', self.frame[10: 10 + 4])
        self.devkey = self.frame[14: 14 + 32]
        self.vertype = self.frame[14 + 32]
        self.flashmap, self.second_boot, self.boot_app = 0, 0, 0
        logger.info('单设备注册, chip: [%s], dev_id: [%s], vertype: [%s]',
                    self.chip_id, self.devkey, self.vertype)
        self.app_id, self.app_key, self.device_tbl_id = yield\
            gl_dbopr.single_device_init(self.chip_id)
        logger.info('单设备 ID: [%d], KEY: [%s]', self.app_id, self.app_key)
        if isinstance(self.app_key, unicode):
            self.app_key = self.app_key.encode('utf-8')
        fmt = b'!IIHBBI32s'
        length = struct.calcsize(fmt)
        body = struct.pack(fmt, length, msg_id, CONST.MSG_SINGLE_DEV_INIT_RSP,
                           0, 0, self.app_id, self.app_key)
        self.proto_inst().transport.write(body)
        self.proto_inst().factory.add_dev(self.app_id, self.app_key,
                                          self.chip_id,
                                          protocol_ref=self.protocol_ref,
                                          devkey=self.devkey,
                                          vertype=self.vertype,
                                          conn_hash=self.conn_hash)
        logger.info('[%d] 单设备注册已完成', self.chip_id)

    def exec_default(self):
        self.api_retval()
        logger.info('[%d] 默认动作，收到返回', self.chip_id)

    def exec_23(self):
        logger.info('[%d] 串口透传的回复', self.chip_id)
        self.api_retval()

    def api_retval(self):
        '''返回API，此处为外部调用本模块的API后给予返回

        / 由于twisted 的异步特性，此处使用了defered以实现异步返回
        / 这里要设置，deferred callback
        / 此函数从最近的callback list中取出对应的，并调用其回调函数
        / 然后删除这个defered
        / 此函数是推送后能立即获得指令执行结果的关键
        '''
        for msgid, deferred in self.deferreds:
            if self.msgid == msgid:
                logger.info('[%d] proc [%d]', self.chip_id, msgid)
                deferred.callback({'code': 0, 'frame': self.frame})
                self.deferreds.remove(tuple([msgid, deferred]))

    def exec_(self, frame):
        '''执行数据分发

        / 通过函数名实现数据的业务分发
        / 未知的数据类型走默认通道直接转发，也可以将其中断
        :param frame:
        '''
        assert len(frame) >= 10
        self.frame = frame
        self.msgid, self.msgtype = struct.unpack(b'!IH', frame[4: 10])

        fn_name = 'exec_%02X' % self.msgtype
        # 无法识别的数据包暂且不断
        if hasattr(self, fn_name):
            fn = getattr(self, fn_name)
            fn()
        else:
            logger.warn('未找到  [%s] 将执行默认动作', fn_name)
            self.exec_default()

    def setDisconnected(self):
        for _, deferred in self.deferreds:
            deferred.callback({'code': 1, 'msg': 'disconnected'})
        self.deferreds = []

    def setDeferred(self, msgid, deferred):
        if deferred:
            self.deferreds.append(tuple([msgid, deferred]))

    def alive_check_after(self, msgid):
        for cur_msgid, deferred in self.deferreds:
            if cur_msgid == msgid:
                deferred.callback({'code': 1, 'msg': 'offline'})
                self.deferreds.remove(tuple([cur_msgid, deferred]))
                self.proto_inst().transport.loseConnection()
                break


class ServerProtocol(protocol.Protocol, TimeoutMixin):
    '''主连接class，负责holding终端连接

    / 参考twisted的示例以理解此class
    / 数据处理由ProtocolProcess 类进行，本class只做连接管理
    / 此处设置了300秒的超时，可以直接修改以更符合业务逻辑，建议保持
    / 拆帧函数为getFrames，如若修改协议，重点考察此函数
    / 建立连接后，20秒内无数据，也判断超时
    '''
    def __init__(self, factory):
        '''
        :type factory: PushFactory
        '''
        self.factory = factory
        self.timeout = 200
        self.timeout_connect = 20

    def connectionMade(self):
        peer = self.transport.getPeer()
        if not peer.host.startswith('10.'):
            logger.info('收到远端连接 [%s:%d]', peer.host, peer.port)
        self.setTimeout(self.timeout)
        self.sid = self.transport.sessionno
        self.peer = self.transport.getPeer()
        self.host = self.peer.host
        self.port = self.peer.port
        self.buf = b''
        self.msgid = 0
        self.procer = ProtocolProcess(weakref.ref(self))
        self.setTimeout(self.timeout_connect)

    def connectionLost(self, reason):
        self.setTimeout(None)
        peer = self.transport.getPeer()
        if not peer.host.startswith('10.'):
            logger.warn('远端断开连接 [%s:%d] => [%s]',
                        peer.host, peer.port, reason.getErrorMessage())
        self.procer.setDisconnected()
        if hasattr(self.procer, 'app_id'):
            # 针对已注册的设备，删除其ref，维护状态机
            self.factory.loseDev(self.procer.conn_hash)
            logger.info('[%d]设备离线, 同步到路由模块', self.procer.chip_id)
            router_facotry.dev_offline(self.procer.app_id,
                                       self.procer.app_key,
                                       self.procer.chip_id,
                                       self.procer.conn_hash)

    def getFrames(self):
        '''拆帧函数

        / 将某一帧，从缓冲区中抽取出来
        / 若不够一帧退出，若超出一帧则取出一帧，剩余的等待余下的数据。
        '''
        if not self.buf:
            return None
        if len(self.buf) <= 8:
            return None
        d_length, = struct.unpack(b'!I', self.buf[:4])
        if len(self.buf) >= d_length:
            frame = self.buf[:d_length]
            self.buf = self.buf[d_length:]
            return frame
        return None

    def manual_alive_check(self, deferred=None):
        msgid = self.push_origin_msg_to_dev(0x18, b'', deferred)
        reactor.callLater(5,  # @UndefinedVariable
                          self.procer.alive_check_after, msgid)

    def push_msg_to_dev(self, msg):
        '''文本指令推送函数

        / 后由于出现了通用指令推送函数，故此函数直接调用了下面的通用推送函数
        :param msg:
        '''
        self.push_origin_msg_to_dev(4, msg)

    def push_origin_msg_to_dev(self, msgtype, content, deferred=None):
        '''向设备、终端推送的通用处理函数

        :param msgtype: int 型，指令十进制的int表示
        :param content: byte型，指令内容
        :param deferred: 为None则不关注返回，否则填入有效的defered
        '''
        assert msgtype <= 0xFF
        logger.info('推送数据至设备，消息类型 [%d], 内容长度 [%d]', msgtype, len(content))
        pack_length = 4 + 4 + 2 + len(content)
        self.msgid += 1
        pack_header = struct.pack(b'!IIH', pack_length, self.msgid, msgtype)
        body = pack_header + content
        if deferred:
            self.procer.setDeferred(self.msgid, deferred)
        logger.info('SENT: [%s]' % repr(body))
        self.transport.write(body)
        return self.msgid

    def dataReceived(self, data):
        '''设备数据到来时处理函数

        / 需深刻理解此函数的运转过程，由于twisted为纯异步处理逻辑
        / 且由于TCP的流特性，数据可能以流的形式逐帧到来
        / 甚至不排除一个字节一个字节的过来，每次出发此函数时，data中甚至只有一个字节
        / 这也是符合TCP协议的，故如若未能取出完整的一帧，则将数据保存在本class的缓冲区 self.buf中
        / 并return，以重新回到twisted的事件回调逻辑中。
        :param data:
        '''
        self.setTimeout(self.timeout)
        logger.info('RECV: [%s]' % repr(data))
        self.buf += data
        while True:
            frame = self.getFrames()
            if not frame:
                break
            try:
                self.procer.exec_(frame)
            except DeviceDisconnected as _:
                logger.warn('连接异常断开')


class PushFactory(protocol.ServerFactory):
    '''ServerProtocol's Factory

    / for twisted.
    '''
    def __init__(self):
        self.protocol = ServerProtocol
        ': :type self._devices: list[DeviceCls]'
        self._devices = []

    def cur_online_devs(self):
        return self._devices

    def find_devs(self, chipid):
        devs = [dev for dev in self._devices if dev.chipid == chipid]
        if not devs:
            logger.warn('未找到设备 [%d]', chipid)
            raise DeviceNotFound('Device [%d] not found.' % chipid)
        if len(devs) > 2:
            logger.warn('发现 [%d] 个设备连接 [%d]', len(devs), chipid)
            raise MultiDeviceFound('MultiDevice found.')
        return devs[0]

    def dev_confirm(self, chipid):
        return [dev.heartbeat(timestamp()) for dev in self._devices
                if dev.chipid == chipid]

    def check_online_manual(self, devobj):
        if devobj.protocol_ref and devobj.protocol_ref():
            devobj.protocol_ref().manual_alive_check()

    def add_dev(self, app_id, app_key, chip_id, **kwargs):
        '''新增设备时在工厂里注册信息

        :type app_id: int
        :type chip_id: int
        :type proto_ref: _weakref.ref
        '''
        assert('protocol_ref' in kwargs)
        assert('devkey' in kwargs)
        assert('vertype' in kwargs)
        assert('conn_hash' in kwargs)
        dev = EspushDevice(appid=app_id,
                           appkey=app_key,
                           chipid=chip_id,
                           devkey=kwargs['devkey'],
                           vertype=kwargs['vertype'],
                           protocol_ref=kwargs['protocol_ref'],
                           conn_hash=kwargs['conn_hash'])
        # 如果此devices.chipid在本进程内有重复，则检查前者
        for devobj in self._devices:
            if devobj.chipid == chip_id:
                logger.warn('重复设备编号，手动刷新前者。')
                self.check_online_manual(devobj)
        self._devices.append(dev)
        router_facotry.new_dev_online(app_id, app_key, chip_id,
                                      devkey=kwargs['devkey'],
                                      vertype=kwargs['vertype'],
                                      conn_hash=kwargs['conn_hash'])

    def get_server_protocol(self, chipid):
        '''
        :type chipid: int
        :rtype: ServerProtocol
        '''
        ': :type client: EspushDevice'
        client = self.find_devs(chipid)
        if client.protocol_ref is None:
            logger.warn('protocol_ref对象为空，程序逻辑错误')
            raise DeviceOfflined('Device offline.')
        ': :type proto_inst: ServerProtocol'
        proto_inst = client.protocol_ref()
        if proto_inst is None:
            logger.warn('protocol_ref指向对象为空，设备已下线')
            raise DeviceOfflined('Device offline.')
        return proto_inst

    def is_alive(self, chipid):
        '''存活检测

        / protocol.Protocol.transport.connected是twisted的存活检测方式
        :param chipid:
        '''
        try:
            return self.get_server_protocol(chipid).transport.connected
        except DeviceOfflined as _:
            return False
        except DeviceNotFound as _:
            return False

    def manual_is_alive(self, chipid, deferred):
        '''
        @summary: 通过手动控制发送TCP包来检查客户端是否在线，延迟时间暂定5秒
        :param chipid:
        @return: 返回'offline'，已确定离线，其他，暂未知
        '''
        try:
            ': :type proto_inst: ServerProtocol'
            proto_inst = self.get_server_protocol(chipid)
        except DeviceOfflined as _:
            return 'offline'
        except DeviceNotFound as _:
            return 'offline'
        if not proto_inst.transport.connected:
            return 'offline'
        return proto_inst.manual_alive_check(deferred)

    def push_msg(self, chipid, content):
        if self.is_alive(chipid):
            logger.info('设备 %d 存活，文本数据推送', chipid)
            ': :type proto_inst: ServerProtocol'
            proto_inst = self.get_server_protocol(chipid)
            proto_inst.push_msg_to_dev(content)

    def push_data_dev(self, chipid, msgtype, content, deferred):
        if not self.is_alive(chipid):
            return deferred.callback({'code': 1, 'msg': 'not connected.'})
        ': :type proto_inst: ServerProtocol'
        proto_inst = self.get_server_protocol(chipid)
        cur_msgid = (proto_inst.push_origin_msg_to_dev(msgtype,
                                                       content, deferred))
        reactor.callLater(5,  # @UndefinedVariable
                          proto_inst.procer.alive_check_after, cur_msgid)

    def loseDev(self, conn_hash):
        '''与终端的连接丢失时，需要维护状态机'''
        self._devices[:] = [dev for dev in self._devices
                            if dev.conn_hash != conn_hash]

    def buildProtocol(self, addr):
        p = self.protocol(self)
        return p


class RouteProtocol(JSONProtocol):
    def __init__(self):
        JSONProtocol.__init__(self, svc_cfg)

    def pushmsg_to_dev(self, cmdobj):
        d = Deferred()
        d.addCallback(self._delayCallback, cmdobj)
        d.addErrback(self._errCallback, cmdobj)
        chipid = cmdobj['chipid']
        if isinstance(chipid, unicode):
            chipid = chipid.encode('utf-8')
        msgtype = cmdobj['msgtype']
        if isinstance(msgtype, unicode):
            msgtype = msgtype.encode('utf-8')
        content = cmdobj['body']
        if isinstance(content, unicode):
            content = content.encode('utf-8')
        client_factory.push_data_dev(chipid, msgtype, content, d)

    def _errCallback(self, fail, cmdobj):
        logger.error('回调出错，错误详情: ')
        logger.error(fail.getTraceback())

    def _delayCallback(self, reason, cmdobj):
        assert(isinstance(reason, dict))
        assert('code' in reason)
        assert('msgid' in cmdobj)
        rspObj = {
            'msgid': cmdobj['msgid'],
        }
        rspObj.update(reason)
        pprint.pprint(rspObj)
#         if 'frame' in rspObj:
#             rspObj['frame'] = base64.b64encode(rspObj['frame'])
        rspbuf = self.makePacket('pushmsg_to_dev', 'rsp', rspObj)
        self.transport.write(rspbuf)

    def online_clients(self):
        return client_factory.cur_online_devs()


class RouteFactory(JSONClientFactory):
    def __init__(self):
        JSONClientFactory.__init__(self)
        self.protocol = RouteProtocol


def checkIp(ip):
    try:
        return socket.inet_aton(ip)
    except OSError as _:
        return None

def checkAddr(addr):
    ip, port = addr.split(':')
    if not to_int(port):
        return None
    if not checkIp(ip):
        return None
    return True


def parseArgs(argv):
    args = argparse.ArgumentParser()
    args.add_argument('-r', '--router',
                      help="连接Router的地址端口,类似 127.0.0.1:10010")
    args.add_argument("-l", '--logging', help="日志等级，DEBUG, INFO, WARN, ERROR, FATAL")
    args.add_argument("-o", '--outer', help='服务外部可连接的地址与端口')
    args.add_argument("-d", '--db', help='数据库连接配置信息，使用Postgres数据库，字符串如 user:pwd:dbname@host')
    result = args.parse_args(argv)
    print('ROUTER: [%s]\nLOGGING: [%s]\nOUTER: [%s]\nDB: [%s]' % (result.router, result.logging, result.outer, result.db))
    if result.logging not in ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL']:
        print('ERROR logging')
    if not checkAddr(result.router):
        print("ERROR router")
    if not checkAddr(result.outer):
        print("ERROR outer")
    dbuserpwdinst, host = result.db.split('@')
    dbuser, dbpwd, dbinst = dbuserpwdinst.split(':')
    return result


if __name__ == '__main__':
    '''启动初始化函数

    espush.cn推送服务器

    使用pure python、pure socket开发的tcp 推送服务器，与设备通过长连接保持，以实现对设备的实时控制
    暂且只支持ESP8266系列，但服务端无具体要求，只要适配协议，亦可接入其他设备。

    Created on 2015年2月11日

    @author: Sunday

    '''
    reactor.suggestThreadPoolSize(30)  # @UndefinedVariable
    # 读取配置文件
    svc_cfg = SvcConfig('espush.ini', 'svc_espush')
    # 确认IP地址
    if svc_cfg.outerip not in our_ips() and not svc_cfg.outer_ignore_mismatch:
        sys.stderr.write('外部IP配置可能错误,检查或设置 ignore_mismatch\n')
        sys.exit(1)
    # 日志初始化
    initlog(level=svc_cfg.loglevel)
    logger.info('svctype: [%s], loglevel: [%s], '
                'router: [%s:%d], outer: [%s:%d]',
                svc_cfg.svctype, svc_cfg.loglevelname,
                svc_cfg.routerip, svc_cfg.routerport,
                svc_cfg.outerip, svc_cfg.outerport)
    # 初始化数据库
    gl_dbopr = DBopr(svc_cfg.dbpath)
    # 协议端口
    client_factory = PushFactory()
    reactor.listenTCP(svc_cfg.outerport,  # @UndefinedVariable
                      client_factory)
    logger.info('启用端口监听 [%d]', svc_cfg.outerport)
    # 往路由的连接
    router_facotry = RouteFactory()
    reactor.connectTCP(svc_cfg.routerip,  # @UndefinedVariable
                       svc_cfg.routerport, router_facotry)
    # 写入进程pid
    write_pid_file()
    reactor.run()  # @UndefinedVariable
