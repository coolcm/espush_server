#!/usr/bin/env python
# encoding: utf-8

from __future__ import unicode_literals
from __future__ import print_function


import sys
import json
import copy
import random
import struct
import pprint

try:
    import cPickle as pickle
except ImportError as _:
    import pickle

import logging
import weakref
import datetime
import ConfigParser

from collections import namedtuple

from twisted.internet import protocol, reactor
from twisted.web.server import Site, NOT_DONE_YET
from twisted.web.resource import Resource
from twisted.internet.defer import Deferred

from common import write_pid_file, logger, initlog


Service = namedtuple('Service', ['svctype', 'gpid', 'outerip', 'outerport',
                                 'connection', 'regtime'])
# OnlineDevice 的connection是gwsvc的connection
OnlineDevice = namedtuple('OnlineDevice', ['appid', 'appkey', 'chipid', 'gpid',
                                           'connection', 'regtime', 'kwargs',
                                           'conn_hash'])
PushMessage = namedtuple('PushMessage', ['deferred', 'msgid', 'msgtype',
                                         'body', 'chipid', 'gpid',
                                         'timeout_chkid'])


def to_int(string):
    '''int的无异常版本

    / Python默认的int函数可能抛出异常
    / 导致到处的 try，catch，太难看
    / 此处使用返回值形式代替
    :param s:
    '''
    try:
        return int(string)
    except ValueError as _:
        return None


class RouteTable(object):
    def __init__(self):
        self.__svcs = []
        self.__devices = []
        self.__msgs = []
        self.__curmsgid = 0

    def devices(self):
        return self.__devices

    def find_devs_appid(self, appid):
        return [dev for dev in self.__devices if dev.appid == appid]

    def clear_dev(self):
        self.__devices = []

    def add_svc(self, routeobj):
        self.__svcs.append(routeobj)

    def add_dev(self, onlinedevobj):
        self.__devices.append(onlinedevobj)

    def gpidNode(self, gpid):
        nodes = [svc for svc in self.__svcs if svc.gpid == gpid]
        if len(nodes) > 1:
            raise Exception('GPID重复')
        return nodes[0]

    def del_svc(self, gpid):
        # 所有此连接上的msgs也调用之，并清除
        msgs = [msg for msg in self.__msgs if msg.gpid == gpid]
        for msg in msgs:
            if msg.deferred is not None:
                msg.deferred.errback(Exception("device offline"))
        # 删除其服务条目
        self.__svcs[:] = [svc for svc in self.__svcs if svc.gpid != gpid]
        # 同步线上设备条目
        self.__devices[:] = [dev for dev in self.__devices
                             if not dev.gpid == gpid]

    def rm_dev_conn_hash(self, conn_hash):
        self.__devices[:] = [dev for dev in self.__devices
                             if dev.conn_hash != conn_hash]

    def del_dev(self, appid, appkey, chipid):
        self.__devices[:] = [dev for dev in self.__devices
                             if not (dev.appid == appid and
                                     dev.appkey == appkey and
                                     dev.chipid == chipid)]

    def getAvailableNode(self, svctype):
        svcnodies = [el for el in self.__svcs if el.svctype == svctype]
        if svcnodies:
            return random.choice(svcnodies)
        return None

    def getNodeConnection(self, chipid):
        return [dev for dev in self.__devices
                if dev.chipid == chipid]

    def online_devices(self):
        return copy.deepcopy(self.__devices)

    def get_msgid(self):
        self.__curmsgid += 1
        return self.__curmsgid

    def msgfromid(self, msgid):
        msgs = [msg for msg in self.__msgs if msg.msgid == msgid]
        if not msgs:
            logger.info('收到来自服务进程 的数据但未找到源请求')
            raise Exception("data from svc, but msgid not found")
        if len(msgs) > 1:
            logger.warn('收到来自服务进程的数据，找到超过一个来源请求，异常')
            raise Exception('data from svc, but multi msgid')
        return msgs[0]

    def recover_msg(self, cmdObj):
        assert('msgid' in cmdObj)
        msg = self.msgfromid(cmdObj['msgid'])
        if msg.deferred:
            msg.deferred.callback(cmdObj)
        if msg.timeout_chkid:
            logger.info('取消返回定时器 msgid: [%d]', msg.msgid)
            msg.timeout_chkid.cancel()
        self.__msgs.remove(msg)

    def timeout_check(self, msgid):
        try:
            msg = self.msgfromid(msgid)
        except Exception as _:
            logger.info('msg未找到，数据已返回')
            return None
        if msg.deferred:
            msg.deferred.errback(Exception("Device offline"))
        self.__msgs.remove(msg)

    def msg_dispatch(self, msgtype, msgbody, chipid, deferred):
        '''
        :summary: 与上面msg_push函数不同的是，此处需要deferred
        :param msgtype:
        :param msgbody:
        :param chipid:
        :param deferred:
        '''
        services = self.getNodeConnection(chipid)
        if not services:
            logger.warn('服务进程已不在线')
            if deferred is not None:
                deferred.errback(Exception("svc offline"))
            return None
        service = services[0]
        conn = service.connection()
        if conn is None:
            logger.warn('JSON连接已断开，但残留数据未删除')
            self.del_svc(service.gpid)
            if deferred is not None:
                deferred.errback(Exception("server error"))
            return None
        # typeof(connection) == weakref.ref
        msgid = self.get_msgid()
        pushmsg = PushMessage(deferred=deferred,
                              msgid=msgid,
                              msgtype=msgtype,
                              body=msgbody,
                              chipid=chipid,
                              gpid=service.gpid,
                              timeout_chkid=None)
        # 如果deferred为空，证明不关注回复，故无需保存，同时设置超时
        if deferred:
            chkid = reactor.callLater(8,  # @UndefinedVariable
                                      self.timeout_check, msgid)
            pushmsg = PushMessage(deferred=deferred,
                                  msgid=msgid,
                                  msgtype=msgtype,
                                  body=msgbody,
                                  chipid=chipid,
                                  gpid=service.gpid,
                                  timeout_chkid=chkid)
            self.__msgs.append(pushmsg)
        # 数据投递到对端，只需要删除无法序列化的 deferred 对象
        msgargs = pushmsg._asdict()
        del msgargs['deferred']
        del msgargs['timeout_chkid']
        conn.pushmsg_gw_dev(**msgargs)

    def online_dev_appid(self, appid):
        return [dev.chipid for dev in self.__devices if dev.appid == appid]


class JSONProtocol(protocol.Protocol):
    def connectionMade(self):
        logger.info('收到服务进程的连接')
        self.buf = b''
        self.gpid = ''

    def connectionLost(self, reason):
        logger.info('服务进程关闭')
        if self.gpid:
            logger.info('离线所有该服务进程下的设备 [%s]', self.gpid)
            gl_routetable.del_svc(self.gpid)

    def makePacket(self, cmdType, cmdPath, cmdObj):
        assert(isinstance(cmdObj, dict))
        assert(cmdPath in ['req', 'rsp'])
        cmdObj['cmdType'] = cmdType
        cmdObj['cmdPath'] = cmdPath
        jsonbuf = pickle.dumps(cmdObj)
        return b''.join([struct.pack(b'!I', len(jsonbuf) + 4), jsonbuf])

    def svc_register(self, cmdObj):
        assert('outerip' in cmdObj)
        assert('outerport' in cmdObj)
        assert('svctype' in cmdObj)
        assert('gpid' in cmdObj)
        outerip = cmdObj['outerip']
        outerport = cmdObj['outerport']
        svctype = cmdObj['svctype']
        gpid = cmdObj['gpid']
        self.gpid = gpid
        cur_time = datetime.datetime.now()
        svcroute = Service(svctype=svctype,
                           gpid=gpid,
                           outerip=outerip,
                           outerport=outerport,
                           connection=weakref.ref(self),
                           regtime=cur_time)
        logger.info('服务注册: [%s], [%s], [%s:%d]',
                    svctype, gpid, outerip, outerport)
        gl_routetable.add_svc(svcroute)
        svcreg_rsp = {'code': 0}
        rspbuf = self.makePacket('svc_register', 'rsp', svcreg_rsp)
        self.transport.write(rspbuf)

    def get_frame(self):
        if len(self.buf) < 4:
            return
        length, = struct.unpack(b'!I', self.buf[:4])
        if len(self.buf) < length:
            return
        frame = self.buf[:length]
        self.buf = self.buf[length:]
        return frame

    def devs_sync(self, cmdobj):
        assert('devices' in cmdobj)
        devices = cmdobj['devices']
        cur_time = datetime.datetime.now()
        gl_routetable.clear_dev()
        for dev in devices:
            assert('appid' in dev)
            assert('appkey' in dev)
            assert('chipid' in dev)
            appid = dev['appid']
            appkey = dev['appkey']
            chipid = dev['chipid']
            conn_hash = dev['conn_hash']
            onlinedev = OnlineDevice(appid=appid,
                                     gpid=self.gpid,
                                     appkey=appkey,
                                     chipid=chipid,
                                     connection=weakref.ref(self),
                                     regtime=cur_time,
                                     conn_hash=conn_hash,
                                     kwargs=dev)
            gl_routetable.add_dev(onlinedev)
            logger.info('设备注册: [%d], [%s], [%d]', appid, appkey, chipid)
            logger.info('%s', pprint.pformat(dev))
        cmdObj = {'code': 0}
        rspbuf = self.makePacket('devs_sync', 'rsp', cmdObj)
        self.transport.write(rspbuf)

    def dev_unregister(self, cmdobj):
        # appid = cmdobj['appid']
        # appkey = cmdobj['appkey']
        # chipid = cmdobj['chipid']
        conn_hash = cmdobj['conn_hash']
        gl_routetable.rm_dev_conn_hash(conn_hash)
        # gl_routetable.del_dev(appid, appkey, chipid)

    def pushmsg_gw_dev(self, **kwargs):
        cmdObj = {}
        cmdObj.update(kwargs)
        reqbuf = self.makePacket('pushmsg_gw_dev', 'req', cmdObj)
        self.transport.write(reqbuf)

    def rsp_pushmsg_gw_dev(self, cmdobj):
        assert('msgid' in cmdobj)
        pprint.pprint(cmdobj)
        msgid = cmdobj['msgid']
        logger.info('来自gwsvc的数据返回 msgid: [%d]', msgid)
        gl_routetable.recover_msg(cmdobj)

    def dev_register(self, cmdobj):
        assert('appid' in cmdobj)
        assert('appkey' in cmdobj)
        assert('chipid' in cmdobj)
        assert('conn_hash' in cmdobj)
        appid = cmdobj['appid']
        appkey = cmdobj['appkey']
        chipid = cmdobj['chipid']
        conn_hash = cmdobj['conn_hash']
        cur_time = datetime.datetime.now()
        onlinedev = OnlineDevice(appid=appid,
                                 gpid=self.gpid,
                                 appkey=appkey,
                                 chipid=chipid,
                                 connection=weakref.ref(self),
                                 regtime=cur_time,
                                 conn_hash=conn_hash,
                                 kwargs=cmdobj)
        gl_routetable.add_dev(onlinedev)
        logger.info('设备注册: [%d], [%s], [%d]', appid, appkey, chipid)
        logger.info('[%s]', pprint.pformat(cmdobj))
        devreg_rsp = {'code': 0}
        rspbuf = self.makePacket('dev_register', 'rsp', devreg_rsp)
        self.transport.write(rspbuf)

    def proc_frame(self, cmdobj):
        cmdType = cmdobj.get('cmdType')
        cmdPath = cmdobj.get('cmdPath')
        if cmdType == 'svc_register' and cmdPath == 'req':
            logger.info('收到服务注册请求')
            self.svc_register(cmdobj)
        elif cmdType == 'dev_register' and cmdPath == 'req':
            logger.info('收到设备上线请求')
            self.dev_register(cmdobj)
        elif cmdType == 'devs_sync' and cmdPath == 'req':
            logger.info('设备数据同步请求')
            self.devs_sync(cmdobj)
        elif cmdType == 'dev_unregister' and cmdPath == 'req':
            logger.info('设备离线请求')
            self.dev_unregister(cmdobj)
        elif cmdType == 'pushmsg_to_dev' and cmdPath == 'rsp':
            logger.info('数据推送来自服务进程的回复')
            self.rsp_pushmsg_gw_dev(cmdobj)
        else:
            logger.warn('未知服务类型请求')
            self.transport.loseConnection()

    def dataReceived(self, data):
        self.buf += data
        logger.info('收到来自服务进程的数据')
        while True:
            frame = self.get_frame()
            if not frame:
                break
            cmdobj = pickle.loads(frame[4:])
            assert(isinstance(cmdobj, dict))
            assert('cmdType' in cmdobj)
            assert('cmdPath' in cmdobj)
            self.proc_frame(cmdobj)


class JSONServerFactory(protocol.ServerFactory):
    protocol = JSONProtocol


class GetSvcNode(Resource):
    def render_GET(self, request):
        svctypes = request.args.get('protocol')
        if not svctypes:
            logger.warn('获取节点时未指定协议')
            request.setResponseCode(400)
            return json.dumps({'msg': 'error.'})
        svctype = svctypes[0]
        svcnode = gl_routetable.getAvailableNode(svctype)
        if svcnode:
            nodeinfo = {'host': svcnode.outerip, 'port': svcnode.outerport}
            return json.dumps(nodeinfo)
        return b'{}'


class OnlineDevs(Resource):
    def render_GET(self, request):
        fields = ['appid', 'appkey', 'chipid']
        onlinedevs = gl_routetable.online_devices()
        jsondevs = [{field: dev.__dict__[field] for field in fields}
                    for dev in onlinedevs]
        return json.dumps(jsondevs)


class PushDevOriginMsgHdl(Resource):
    def _delayRender(self, reason, request):
        assert(isinstance(reason, dict))
        if 'code' in reason and reason['code'] == 0:
            logger.info('收到来自终端的数据，返回到API客户端')
            frame = reason.get('frame') if 'frame' in reason else ''
            # request.write(json.dumps({'frame': frame, 'code': 0}))
            if isinstance(frame, unicode):
                frame = frame.encode('utf-8')
            request.write(frame)
        else:
            request.setResponseCode(500)
            request.write(json.dumps({'code': 1, 'msg': 'unknown error'}))
        request.finish()

    def _errRender(self, fail, request):
        logger.error(fail.getTraceback())
        request.setResponseCode(500)
        request.write(json.dumps({'code': 1, 'msg': 'espush gateway error'}))
        request.finish()

    def render_POST(self, request):
        '''
        :summary: 需要加入超时判断机制
        :param request:
        '''
        msgtypes = request.args.get('msgtype')
        if not msgtypes:
            logger.info('数据直接推送接口，缺少msgtype')
            request.setResponseCode(400)
            return json.dumps({'msg': 'msgtype empty, ignored.'})
        msgtype = to_int(msgtypes[0])
        content = request.content.read()
        devs = request.args.get('dev')
        if not devs:
            logger.info('通用数据推送接口 未获得设备号')
            request.setResponseCode(400)
            return json.dumps({'msg': 'devs empty'})
        if len(devs) > 1:
            logger.info('推送到多个设备请分次调用或使用app参数')
            request.setResponseCode(400)
            return json.dumps({'msg': 'devs largger than one.'})
        if not to_int(msgtype) or to_int(msgtype) > 0xFF:
            logger.info('消息类型为非整形或数值过大，错误')
            request.setResponseCode(400)
            return json.dumps({'msg': 'msgtype error'})
        chipid = to_int(devs[0])
        logger.info('测试数据推送接口至设备 %d', chipid)
        if not gl_routetable.getNodeConnection(chipid):
            logger.warn('已不确定设备是否在线，放弃推送')
            request.setResponseCode(502)
            return json.dumps({'msg': 'devices status unknown.'})
        d = Deferred()
        d.addCallback(self._delayRender, request)
        d.addErrback(self._errRender, request)
        # 把数据发送到服务器进程
        gl_routetable.msg_dispatch(msgtype, content, chipid, d)
        return NOT_DONE_YET


class AllOnlineHdl(Resource):
    def render_GET(self, request):
        devs = gl_routetable.devices()
        apps = [dev.appid for dev in devs]
        confirms = [dev.chipid for dev in devs]
        return json.dumps([{
            'appid': dev.appid,
            'chipid': dev.chipid
                           } for dev in devs])
        # return json.dumps({'confirms': confirms, 'apps': apps})


class OnLineHdl(Resource):
    def render_GET(self, request):
        apps = request.args.get('app')
        if not apps:
            logger.warn('通过接口查询在线设备，未指定appid')
            request.setResponseCode(400)
            return request.write(json.dumps({"msg": "args error."}))
        dev_objs = []
        for _appid in apps:
            appid = to_int(_appid)
            if not appid:
                logger.warn('接口参数错误，app需为整形')
                request.setResponseCode(400)
                return request.write(json.dumps({"msg": "args type error."}))
            app_devs = gl_routetable.find_devs_appid(appid)
            dev_objs.extend([{
                         'appid': dev.appid,
                         'devid': dev.chipid,
                         'chipid': dev.chipid,
                         'latest': dev.regtime.strftime('%Y-%m-%d %H:%M:%S'),
                         'vertype': (0 if 'vertype' not in dev.kwargs
                                     else dev.kwargs['vertype']),
                         'devkey': ('' if 'devkey' not in dev.kwargs
                                    else dev.kwargs['devkey']),
                         } for dev in app_devs])
        return json.dumps(dev_objs)


class PushMsgHdl(Resource):
    '''设备文本指令推送API，在有了后两个接口的情况下，此接口已近乎废弃  '''
    def render_POST(self, request):
        apps = request.args.get('app')
        chipids = request.args.get('dev')
        content = request.content.read()
        if not apps:
            request.setResponseCode(400)
            return json.dumps({'msg': 'app empty'})
        appid = to_int(apps[0])
        if not appid:
            request.setResponseCode(400)
            return b'{"msg": "ERROR APPID"}'
        if chipids:
            chipids = [to_int(el) for el in chipids if to_int(el)]
            logger.info('定向推送至 %s', pprint.pformat(chipids))
        else:
            # 群推, 这里需要确定是个所有设备推，还是在线设备，暂定在线设备
            logger.info('群推至应用 [%d]', appid)
            chipids = gl_routetable.online_dev_appid(appid)
        for chipid in chipids:
            logger.info('数据推送至 %d', chipid)
            gl_routetable.msg_dispatch(0x04, content, chipid, None)
        return b'{"msg": "OK"}'


class PushAppOriginMsgHdl(Resource):
    '''通用推送API，推送到某个设备分类，并不等待返回

    / 通过指定目标设备的dev appid与msgtype，以及POST的content，实现向设备推送任何指令
    '''
    def render_POST(self, request):
        msgtypes = request.args.get('msgtype')
        if not msgtypes:
            logger.info('数据直接推送接口，缺少msgtype')
            request.setResponseCode(400)
            return json.dumps({'msg': 'msgtype empty, ignored.'})
        msgtype = to_int(msgtypes[0])
        content = request.content.read()
        apps = request.args.get('app')
        if not apps:
            logger.info('通用数据推送接口 未获得app编号')
            request.setResponseCode(400)
            return json.dumps({'msg': 'devs empty'})
        if len(apps) > 1:
            logger.info('不可以推送到多个APP')
            request.setResponseCode(400)
            return json.dumps({'msg': 'devs largger than one.'})
        appid = to_int(apps[0])
        chipids = gl_routetable.online_dev_appid(appid)
        if not chipids:
            logger.warn('app 无在线设备')
            request.setResponseCode(400)
            return json.dumps({'msg': 'apps has not online dev.'})
        logger.info('找到在线设备 %s', pprint.pformat(chipids))
        for chipid in chipids:
            logger.info('数据推送至 %d', chipid)
            gl_routetable.msg_dispatch(msgtype, content, chipid, None)
        return json.dumps({'msg': 'OK'})


class DevRefreshHdl(Resource):
    '''
    :summary: 设备手动强制刷新的API。
    '''
    @staticmethod
    def _delayRender(reason, request):
        assert isinstance(reason, dict)
        print(pprint.pformat(reason))
        if 'code' in reason and reason['code'] == 0:
            logger.info('收到来自终端的数据，返回到API客户端')
            body = reason['frame']
        else:
            logger.info('刷新终端时错误，返回API')
            body = reason['msg']
        if isinstance(body, unicode):
            body = body.encode('utf-8')
        request.write(body)
        request.finish()

    def _errRender(self, fail, request):
        logger.error(fail.getTraceback())
        request.write(b'offline')
        request.finish()

    def render_POST(self, request):
        chipids = request.args.get('chipid')
        if not chipids:
            logger.info('设备手动刷新接口，未获得设备ID号')
            request.SetResponseCode(400)
            return json.dumps({'msg': 'chipid empty'})
        chipid = to_int(chipids[0])
        logger.info('手动检查设备 [%d] 是否在线', chipid)
        d = Deferred()
        d.addCallback(self._delayRender, request)
        d.addErrback(self._errRender, request)
        # 把数据发送到服务器进程
        gl_routetable.msg_dispatch(0x18, b'', chipid, d)
        return NOT_DONE_YET


def web_init():
    root = Resource()
    root.putChild('node', GetSvcNode())
    root.putChild('online', OnlineDevs())
    root.putChild('all_online', AllOnlineHdl())
    root.putChild('online_dev', OnLineHdl())
    root.putChild('pushmsg', PushMsgHdl())
    root.putChild('_push_data', PushDevOriginMsgHdl())
    root.putChild('push_app', PushAppOriginMsgHdl())
    root.putChild('dev_refresh', DevRefreshHdl())
    return root


def load_router_cfg(cfgfilename):
    RouterConfig = namedtuple('RouterConfig',
                              ['listenport', 'apiport', 'loglevel'])
    inicfg = ConfigParser.SafeConfigParser()
    if not inicfg.read(cfgfilename):
        print('配置文件读取失败, 请检查 [%s] 文件是否存在' % cfgfilename)
        return sys.exit(1)
    section = 'router'
    try:
        listenport = inicfg.getint(section, 'listenport')
        apiport = inicfg.getint(section, 'apiport')
        loglevel = inicfg.get(section, 'loglevel')
    except ConfigParser.NoSectionError as e:
        print('配置 [%s] 错误, [%s] -> 未找到' % (cfgfilename, e.section))
        return sys.exit(1)
    except ConfigParser.NoOptionError as e:
        print('配置 [%s] 错误, [%s] -> [%s]'
              % (cfgfilename, e.section, e.option))
        return sys.exit(1)
    except ValueError as e:
        print('配置 [%s] 错误, [%s]' % (cfgfilename, e.message))
        return sys.exit(1)
    levels = ['FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG']
    if loglevel not in levels:
        print('配置 [%s] 错误, [%s] 值异常' % (cfgfilename, 'loglevel'))
        return sys.exit(1)
    return RouterConfig(listenport=listenport,
                        apiport=apiport,
                        loglevel=loglevel)


def main():
    logger.info('路由模块已启动')
    reactor.run()  # @UndefinedVariable


if __name__ == '__main__':
    loglevels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARN': logging.WARN,
        'ERROR': logging.ERROR,
        'FATAL': logging.FATAL
    }
    router_cfg = load_router_cfg('espush.ini')
    initlog(level=loglevels[router_cfg.loglevel])
    # router svc
    gwsvc_factory = JSONServerFactory()
    listenport = router_cfg.listenport
    reactor.listenTCP(listenport, gwsvc_factory)  # @UndefinedVariable
    gl_routetable = RouteTable()
    # web interface
    web_factory = Site(web_init())
    web_factory.displayTracebacks = False
    apiport = router_cfg.apiport
    reactor.listenTCP(apiport, web_factory)  # @UndefinedVariable
    write_pid_file()
    main()
