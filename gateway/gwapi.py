#!/usr/bin/env python
# encoding: utf-8

from __future__ import unicode_literals
from __future__ import print_function

import tornado.platform.twisted

from twisted.internet import reactor

import tornado.web
import tornado.ioloop
import tornado.websocket

from twisted.internet import protocol
from gwsvc.common import JSONProtocol, SvcConfig
from twisted.internet.defer import Deferred


class RouteProtocol(JSONProtocol):
    def __init__(self):
        JSONProtocol.__init__(self, svc_cfg)

    def pushmsg_to_dev(self, cmdobj):
        d = Deferred()
        d.addCallback(self._delayCallback, cmdobj)
        chipid = cmdobj['chipid']
        if isinstance(chipid, unicode):
            chipid = chipid.encode('utf-8')
        msgtype = cmdobj['msgtype']
        if isinstance(msgtype, unicode):
            msgtype = msgtype.encode('utf-8')
        content = cmdobj['body']
        if isinstance(content, unicode):
            content = content.encode('utf-8')
        mqtt_dev_factory.push_data_dev(chipid, msgtype, content, d)

    def online_clients(self):
        return mqtt_dev_factory.cur_online_devs()


class RouteFactory(JSONClientFactory):
    def __init__(self):
        JSONClientFactory.__init__(self)
        self.protocol = RouteProtocol


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        return self.write({"MSG": "OK"})


class PeerSocketHandler(tornado.websocket.WebSocketHandler):
    clients = {}

    def check_origin(self, origin):
        return True


if __name__ == '__main__':
    reactor.suggestThreadPoolSize(30)  # @UndefinedVariable
    # 读取配置文件
    svc_cfg = SvcConfig('espush.ini', 'svc_mqtt')
    # 日志初始化
    initlog(level=svc_cfg.loglevel)
    logger.info('svctype: [%s], loglevel: [%s], '
                'router: [%s:%d], outer: [%s:%d]',
                svc_cfg.svctype, svc_cfg.loglevelname,
                svc_cfg.routerip, svc_cfg.routerport,
                svc_cfg.outerip, svc_cfg.outerport)
    # 初始化数据库
    gl_dbopr = DBopr(svc_cfg.dbpath)
    application = tornado.web.Application(
        [(r"/node1", MainHandler), ]
    )
    application.listen(8000)
    ioloop_inst = tornado.ioloop.IOLoop.instance()
    tornado.platform.twisted.TornadoReactor(ioloop_inst)
    ioloop_inst.start()
