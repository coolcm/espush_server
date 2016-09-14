#!/usr/bin/env python
# encoding: utf-8

from __future__ import unicode_literals
from __future__ import print_function

import os
import sys
import uuid
import struct
import pickle
import logging
import datetime
import ConfigParser

from twisted.enterprise import adbapi
from twisted.internet.protocol import Protocol, ClientFactory
import netifaces
import socket

logger = logging.getLogger(os.path.basename(sys.argv[0]).split('.')[0])


class SysBaseException(Exception):
    pass


class DeviceNotFound(SysBaseException):
    pass


class MultiDeviceFound(SysBaseException):
    pass


class DeviceOfflined(SysBaseException):
    pass


class ServDbConfigError(SysBaseException):
    pass


class DeviceDisconnected(SysBaseException):
    pass


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


class DeviceCls(object):
    def __init__(self, **kwargs):
        '''
        :type kwargs: dict[str, str]
        '''
        assert('appid' in kwargs)
        assert('appkey' in kwargs)
        assert('chipid' in kwargs)
        self.appid = kwargs['appid']
        self.appkey = kwargs['appkey']
        self.chipid = kwargs['chipid']
        self.kwargs = kwargs


class SvcConfig(object):
    def __init__(self, cfgfilename, svctype):
        '''
        :type cfgfilename: str
        :type svctype: str
        '''
        self.svctype = svctype
        self.__cfg = ConfigParser.SafeConfigParser()
        loglevels = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARN': logging.WARN,
            'ERROR': logging.ERROR,
            'FATAL': logging.FATAL
        }
        if not self.__cfg.read(cfgfilename):
            logger.error('配置文件读取错误 [%s]', cfgfilename)
            return sys.exit(1)
        try:
            self.routerip = self.__cfg.get(svctype, 'routerip')
            self.routerport = self.__cfg.getint(svctype, 'routerport')
            self.outerip = self.__cfg.get(svctype, 'outerip')
            self.outerport = self.__cfg.getint(svctype, 'outerport')
            self.outer_ignore_mismatch = self.__cfg.getboolean(svctype, 'ignore_mismatch')  # @IgnorePep8
            self.loglevelname = self.__cfg.get(svctype, 'loglevel')
            self.dbpath = self.__cfg.get(svctype, 'dbpath')
            self.__items = self.__cfg.items(svctype)
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
        if self.loglevelname not in loglevels:
            print('配置 [%s] 错误, [%s] 值异常' % (cfgfilename, 'loglevel'))
            return sys.exit(1)
        self.loglevel = loglevels[self.loglevelname]


def our_ips():
    ifs = netifaces.interfaces()
    addrs = []
    for iface in ifs:
        addrobj = netifaces.ifaddresses(iface)
        if socket.AF_INET in addrobj:
            addrs.extend([obj['addr'] for obj in addrobj[socket.AF_INET]])
    return addrs


class JSONProtocol(Protocol):
    def __init__(self, cfg):
        '''
        :type cfg: SvcConfig
        '''
        self.__cfg = cfg

    def connectionMade(self):
        logger.info('JSONRPC连接已建立')
        ': :type self.factory JSONClientFactory'
        self.buf = b''
        self.svc_register()
        online_devs = self.online_clients()
        if online_devs:
            self.devs_sync(online_devs)

    def online_clients(self):
        pass

    def devs_sync(self, online_devs):
        '''
        :type online_devs: list[DeviceCls]
        '''
        cmdobjs = []
        for dev in online_devs:
            cmdobj = {}
            cmdobj['appid'] = dev.appid
            cmdobj['appkey'] = dev.appkey
            cmdobj['chipid'] = dev.chipid
            cmdobj['conn_hash'] = dev.conn_hash
            cmdobj['devkey'] = (dev.kwargs['devkey']
                                if 'devkey' in dev.kwargs else '')
            cmdobj['vertype'] = (dev.kwargs['vertype']
                                 if 'vertype' in dev.kwargs else '')
            cmdobjs.append(cmdobj)
        cmdObj = {'devices': cmdobjs}
        syncbuf = self.makePacket('devs_sync', 'req', cmdObj)
        self.transport.write(syncbuf)

    def makePacket(self, cmdType, cmdPath, cmdObj):
        assert(isinstance(cmdObj, dict))
        assert(cmdPath in ['req', 'rsp'])
        cmdObj['cmdType'] = cmdType
        cmdObj['cmdPath'] = cmdPath
        jsonbuf = pickle.dumps(cmdObj)
        return b''.join([struct.pack(b'!I', len(jsonbuf) + 4), jsonbuf])

    def svc_register(self):
        cmdObj = {
            'outerip': self.__cfg.outerip,
            'outerport': self.__cfg.outerport,
            'svctype': self.__cfg.svctype,
            'gpid': uuid.uuid1().hex,
        }
        svc_buf = self.makePacket('svc_register', 'req', cmdObj)
        self.transport.write(svc_buf)

    def connectionLost(self, reason):
        logger.warn('JSONRPC 连接中断')

    def get_frame(self):
        if len(self.buf) < 4:
            return
        length, = struct.unpack(b'!I', self.buf[:4])
        if len(self.buf) < length:
            return
        frame = self.buf[:length]
        self.buf = self.buf[length:]
        return frame

    def dev_register(self, appid, appkey, chipid, **kwargs):
        cmdObj = {
            'appid': appid,
            'appkey': appkey,
            'chipid': chipid
        }
        cmdObj.update(kwargs)
        reqbuf = self.makePacket('dev_register', 'req', cmdObj)
        self.transport.write(reqbuf)

    def dev_unregister(self, appid, appkey, chipid, conn_hash):
        cmdObj = {
            'appid': appid,
            'appkey': appkey,
            'chipid': chipid,
            'conn_hash': conn_hash,
        }
        reqbuf = self.makePacket('dev_unregister', 'req', cmdObj)
        self.transport.write(reqbuf)

    def pushmsg_to_dev(self, cmdobj):
        '''
        :summary: 将数据推送到设备，并返回到路由，记得携带正确的msgid
        还需要记得处理设备不在线、设备连接为空等情况
        推送后需要配置超时检查，处理请求超时的情况
        :param cmdobj:
        '''
        pass

    def proc_frame(self, cmdobj):
        cmdType = cmdobj.get('cmdType')
        cmdPath = cmdobj.get('cmdPath')
        if cmdType == 'svc_register' and cmdPath == 'rsp':
            logger.info('收到服务注册响应')
        elif cmdType == 'devs_sync' and cmdPath == 'rsp':
            logger.info('收到数据同步响应')
        elif cmdType == 'dev_register' and cmdPath == 'rsp':
            logger.info('收到设备注册响应')
        elif cmdType == 'pushmsg_gw_dev' and cmdPath == 'req':
            logger.info('从路由端推送数据到设备')
            self.pushmsg_to_dev(cmdobj)
        else:
            logger.warn('未知服务类型请求')
            logger.info(cmdobj)
            self.transport.loseConnection()

    def dataReceived(self, data):
        self.buf += data
        while True:
            frame = self.get_frame()
            if not frame:
                break
            cmdobj = pickle.loads(frame[4:])
            self.proc_frame(cmdobj)


class JSONClientFactory(ClientFactory):
    def __init__(self):
        ': :type self.router_conn: JSONProtocol'
        self.router_conn = None
        self._callID = None
        self.clock = None

    def retry(self, connector):
        def reconnector():
            self._callID = None
            connector.connect()
        if self.clock is None:
            from twisted.internet import reactor
            self.clock = reactor
        self._callID = self.clock.callLater(1, reconnector)

    def clientConnectionFailed(self, connector, reason):
        logger.warn('连接到路由时失败，准备重连')
        self.router_conn = None
        self.retry(connector)

    def clientConnectionLost(self, connector, reason):
        logger.warn('到路由的连接中断, 准备重连')
        self.router_conn = None
        self.retry(connector)

    def new_dev_online(self, appid, appkey, chipid, **kwargs):
        assert('conn_hash' in kwargs)
        if not self.router_conn:
            logger.warn('到路由的连接已断开，新设备上线通知失败')
            return
        self.router_conn.dev_register(appid, appkey, chipid, **kwargs)

    def dev_offline(self, appid, appkey, chipid, conn_hash):
        if not self.router_conn:
            logger.warn('到路由的连接已断开，设备离线通知失败')
            return
        self.router_conn.dev_unregister(appid, appkey, chipid, conn_hash)

    def buildProtocol(self, addr):
        if self.router_conn:
            logger.warn('到路由的连接已建立，禁止多重连接')
            return None
        self.router_conn = self.protocol()
        self.router_conn.factory = self
        return self.router_conn


def write_pid_file():
    '''
    :summary: 写pid file，便于维护，后续应该写入指定目录，应该支持命令行参数
    '''
    pid = os.getpid()
    filepath = '%s.pid' % os.path.basename(sys.argv[0]).split('.')[0]
    with open(filepath, 'wt') as pidfile:
        pidfile.write('%d' % pid)


def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class DBopr(object):
    @staticmethod
    def get_postgres_pool(dbargs):
        args = dict([el.split('=') for el in dbargs.split('&')])
        if 'port' in args:
            args['port'] = to_int(args['port'])
            if not args['port']:
                args['port'] = 5432
        return adbapi.ConnectionPool('pg8000', **args)

    @staticmethod
    def get_sqlite_pool(dbpath):
        '''
        :summary: 简单的单例处理，并没有做一些metaclass之类的，需要控制只能调用一次
        '''
        base_dir = os.path.dirname(sys.argv[0])
        dbpath = os.path.join(base_dir, dbpath, 'db.sqlite3')
        if not os.path.isfile(dbpath):
            logger.warn('SQLite 数据库连接, 配置: [%s] 错误', dbpath)
            return sys.exit(2)
        return adbapi.ConnectionPool('sqlite3', dbpath,
                                     check_same_thread=False)

    def __init__(self, dbpath):
        # dbpath, sqlite:../../  postgres:user=123&password=132541&host=
        # self.dbpool = self.get_pool(dbpath)
        dbtype, dbargs = dbpath.split(':')
        if dbtype == 'sqlite':
            self.dbpool = self.get_sqlite_pool(dbargs)
        elif dbtype == 'postgres':
            self.dbpool = self.get_postgres_pool(dbargs)

    def upload_msg_save(self, msg):
        def save_rec(txn):
            txn.connection.autocommit = True
            sql = "insert into t_upload_msg"\
                "(body, create_time, recv_time, stat, app_id, dev_id, tag)"\
                " values(%s, %s, %s, 'VALID', %s, %s, %s)"
            body = msg['body']
            create_time = msg['create_time']
            recv_time = msg['recv_time']
            app_id = msg['app_id']
            dev_id = msg['device_tbl_id']
            tag = msg['tag']
            txn.execute(sql, (body, create_time, recv_time,
                              app_id, dev_id, tag, ))
        return self.dbpool.runInteraction(save_rec)

    def chip_to_db(self, chipid, appid):
        def get_or_add_chip_to_db(txn):
            txn.connection.autocommit = True
            txn.execute("select id from t_device where "
                        " stat='OK' and chip=%s and app_id=%s",
                        (chipid, appid))
            result = txn.fetchall()
            if not result:
                logger.info('%d 设备第一次连接，添加数据库记录', chipid)
                txn.execute("insert into t_device(chip, app_id, stat) "
                            " values(%s, %s, 'OK') returning id",
                            (chipid, appid))
                return txn.fetchone()[0]
            chip_rec_id = result[0][0]
            logger.info('%d 设备连接平台', chip_rec_id)
            return result[0][0]
        return self.dbpool.runInteraction(get_or_add_chip_to_db)

    def apps_from_appid_and_key(self, appid, appkey):
        def get_apps(txn):
            txn.execute("select id from t_app where"
                        " id=%s and secret_key=%s and stat='OK'",
                        (appid, appkey))
            return txn.fetchall()
        return self.dbpool.runInteraction(get_apps)

    def get_notice_from_appid(self, app_id):
        def get_noticeobj(txn):
            sql = "select addr, token from t_notice where app_id=%s"
            txn.execute(sql, (app_id, ))
            return txn.fetchall()
        return self.dbpool.runInteraction(get_noticeobj)

    def single_device_init(self, chipid):
        '''
        1, 检查是否有 single app，没有的话 insert 一行，id做为其appid， key做为其appkey
        2, 将上述信息插入device表
        :param chipid:
        '''
        def find_user(txn):
            query_sql = "select id from t_user where is_admin=1"
            txn.execute(query_sql)
            rec = txn.fetchone()
            if not rec:
                logger.warn('无有效的管理员帐号, 出错')
                raise ServDbConfigError("数据库无有效管理员帐号")
            return rec[0]

        def add_single_mode_app(txn):
            txn.connection.autocommit = True
            admin_id = find_user(txn)
            appkey = uuid.uuid1().get_hex()
            new_sql = "insert into t_app"\
                " (app_name, secret_key, user_id, single_mode, stat) "\
                " values('SINGLE_MODE', %s, %s, 1, 'OK') returning id"
            txn.execute(new_sql, (appkey, admin_id))
            return txn.fetchone()[0], appkey

        def find_device(txn, app_id, chip_id):
            '''
            :summary: 此处代码与其上的get_or_add_chip_to_db重复，待改进
            '''
            txn.connection.autocommit = True
            txn.execute("select id from t_device where "
                        " stat='OK' and chip=%s and app_id=%s",
                        (chip_id, app_id))
            result = txn.fetchall()
            if not result:
                logger.info('%d 设备第一次连接，添加数据库记录', chip_id)
                txn.execute("insert into t_device(chip, app_id, stat) "
                            " values(%s, %s, 'OK') returning id",
                            (chip_id, app_id))
                return txn.fetchone()[0]
            chip_rec_id = result[0][0]
            logger.info('%d 设备连接平台', chip_rec_id)
            return result[0][0]

        def injection_single_device_init(txn):
            check_sql = "select id, secret_key from t_app where single_mode=1"
            txn.execute(check_sql)
            rs = txn.fetchone()
            if not rs:
                logger.warn('暂未发现 single_mode apps 记录，新增之')
                appid, appkey = add_single_mode_app(txn)
            else:
                appid, appkey = rs
            dev_tbl_id = find_device(txn, appid, chipid)
            return appid, appkey, dev_tbl_id
        return self.dbpool.runInteraction(injection_single_device_init)


def initlog(level=logging.DEBUG):
    '''
    :summary: 初始化日志，此处未使用twisted 的日志
    '''
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    logfilename = '%s.log' % os.path.basename(sys.argv[0]).split('.')[0]
    logfullfilename = os.path.join(os.path.abspath('..'), 'log', logfilename)
    filehdl = logging.FileHandler(logfullfilename)
    consolehdl = logging.StreamHandler()
    filehdl.setFormatter(fmt)
    consolehdl.setFormatter(fmt)
    logger.addHandler(filehdl)
    logger.addHandler(consolehdl)
    logger.setLevel(level)


if __name__ == '__main__':
    print("HELLO, WORLD.")
