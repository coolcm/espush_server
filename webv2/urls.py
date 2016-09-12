#!/usr/bin/env python
# encoding: utf-8

from __future__ import unicode_literals

from django.conf.urls import patterns, url


urlpatterns = patterns(
    'webv2.views',
    # Examples:
    # url(r'^$', 'wifi.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^$', 'index', name='webv2_index'),
    url(r'^apps/$', 'apps_view', name='webv2_apps'),
    url(r'^remove_app/(\d+)/$', 'remove_app'),
    url(r'^login/$', 'loginview', name='webv2_login'),
    url(r'^register/$', 'register', name='webv2_register'),
    url(r'^pushmsg/$', 'pushmsg', name='webv2_pushmsg'),
    url(r'^push/single_dev/(\d+)/(\d+)/$', 'pushmsg_single_dev'),
    url(r'^devices/$', 'devices', name='webv2_devices'),
    url(r'^logout/$', 'logoutview', name='webv2_logout'),
    url(r'^ota/$', 'otaview'),
    url(r'^history_push/$', 'history_push', name='webv2_history'),
    url(r'^dev_data/$', 'dev_data', name='webv2_data_preview'),
    url(r'^faq/(.*png)$', 'faq_img_view'),
    url(r'^down_roms/(\w+)/$', 'down_latest_rom', name='webv2_down_roms'),
    url(r'^hash_roms/$', 'hash_roms'),
    url(r'^down_apk/$', 'down_apk'),
    url(r'^feedback/$', 'feedback', name='webv2_feedback'),
    url(r'^note_name/(\d+)/(\d+)/$', 'note_name'),
    url(r'^dev_refresh/(\d+)/$', 'dev_refresh'),
    url(r'^data_graphic/$', 'data_graphic', name='webv2_data_graphic'),
    url(r'^notice_opr/(\d+)/$', 'notice_opr'),
    url(r'^notice_api_test/(\d+)/$', 'notice_api_test'),
    url(r'^settings/$', 'user_settings'),
    url(r'^forgot/$', 'pwd_forgot', name='webv2_forgot'),
    url(r'^reset_pwd/$', 'reset_pwd'),
    url(r'^identify_image/$', 'identify_image'),
    url(r'^reboot_dev/(\d+)/$', 'reboot_dev'),
    url(r'^uart_stream_push/(\d+)/$', 'uart_stream_push'),
    url(r'^nodemcu/editor/(\d+)/(\d+)/$', 'nodemcu_editor'),
    url(r'^invoice/$', 'invoice', name='webv2_invoice'),
    url(r'^iocontrol/$', 'iocontrol', name='webv2_iocontrol'),
    url(r'^timertask/$', 'timertask', name='webv2_timertask'),
    url(r'^timertask/remove/(\d+)/$', 'timertask_remove', name='webv2_timertask_remove'),
    url(r'^crontab/apps/$', 'app_list'),
    url(r'^crontab/$', 'crontab', name='webv2_crontab'),
    url(r'^tasklist/$', 'tasklist'),
    url(r'^tasklist/(\d+)/$', 'task_remove'),
    url(r'^tasklog/$', 'tasklog'),
    url(r'^newtask/$', 'newtask'),
    url(r'^crontab/appendlog/$', 'appendlog'),
    url(r'^timestamp/$', 'get_timestamp'),
    # ADMIN BEGIN
    url(r'^admin/roms/$', 'admin_rom_view', name='webv2_admin_roms'),
    url(r'^admin/roms/(\d+)/$', 'admin_down_romfile'),
    url(r'^admin/devices/online/$', 'admin_online_devices', name="webv2_admin_online_devices"),
    url(r'^admin/users/$', 'admin_users', name="webv2_admin_users"),
    url(r'^admin/wechat_users/$', 'admin_wechat_users', name="webv2_admin_wechat_users"),
    url(r'^admin/crontabs/$', 'admin_crontabs', name="webv2_admin_crontabs"),
    url(r'^admin/apps/$', 'admin_apps', name="webv2_admin_apps"),
)
