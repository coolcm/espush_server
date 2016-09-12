
from __future__ import unicode_literals
from __future__ import print_function


class EspushBaseException(Exception):
    pass


class EspushException(EspushBaseException):
    pass


class ServerConfigureException(EspushException):
    pass


class DeviceOfflineExp(EspushException):
    pass


class DeviceNotFoundExp(EspushException):
    pass


class AppNotFoundExp(EspushException):
    pass


class MultiDeviceFoundExp(EspushException):
    pass


class MultiAppFoundExp(EspushException):
    pass


class ArgumentError(EspushException):
    pass


class GatewayApiError(EspushException):
    pass


class GatewayTimeoutError(EspushException):
    pass


class GatewayCallError(EspushException):
    pass


class WechatAPICallError(EspushException):
    pass


__all__ = ['EspushException', 'DeviceOfflineExp', 'DeviceNotFoundExp',
           'AppNotFoundExp', 'MultiDeviceFoundExp', 'MultiAppFoundExp',
           'ArgumentError', 'GatewayApiError', 'GatewayTimeoutError',
           'GatewayCallError', 'ServerConfigureException', 'WechatAPICallError',]
