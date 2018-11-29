#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: cucker0

## ali DNS 云解析API
# https://help.aliyun.com/document_detail/29744.html?spm=a2c4g.11186623.6.617.5d0672edaYqfa7

import hashlib
import requests
import hmac
import time
import base64
import json
import uuid
from urllib import parse


class Sign(object):
    """
    签名机制
    https://help.aliyun.com/document_detail/29747.html?spm=a2c4g.11186623.6.620.600111b6pEpZjE
    """
    def __init__(self, secretKey):
        self.secretKey = secretKey

    def url_encoder(self, s):
        ret = parse.quote(s)
        ret = ret.replace('+', '%20')
        ret = ret.replace('*', '%2A')
        ret = ret.replace('%7E', '~')
        return ret

    # 生成签名串
    def make(self, params, method='GET'):
        params_join = "&".join(k + "=" + str(self.url_encoder(params[k])) for k in sorted(params.keys()))
        srcStr = method.upper() + '&%2F&' +  self.url_encoder(params_join)
        hashed = hmac.new(bytes(self.secretKey, encoding='utf8'), bytes(srcStr, encoding='utf8'), hashlib.sha1)
        return base64.b64encode(hashed.digest())

class DnsHelper(object):
    """
    DNS相关操作类
    """
    AccessKeyId = 'LTAxxxqA89xxxx'
    AccessKeySecret = 'xxxVUwf4MOjixxxXgIlbncCdxxx'

    requestHost = 'alidns.aliyuncs.com'
    requestUri = '/'

    def __init__(self):
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.params = {
            'Format': 'JSON',
            'Version': '2015-01-09',
            'AccessKeyId': self.AccessKeyId,
            'SignatureVersion': '1.0',
            'SignatureMethod': 'HMAC-SHA1',
            # 'SignatureNonce': str( random.randint(10000000, 99999999) ),
            'SignatureNonce': str(uuid.uuid1()),
            'Timestamp': self.timestamp
            }
        self.url = 'https://%s%s' % (DnsHelper.requestHost, DnsHelper.requestUri)
        self.AccessKeySecret += '&'         # 用于加密的Secret为 AccessKeySecret加上&字符

    def get_domain_list(self, PageNumber='1', PageSize='100', KeyWord='', GroupId=''):
        """
        获取域名列表
        :param PageNumber:当前页数，起始值为1，默认为1(非必要参数)
        :param PageSize:分页查询时设置的每页行数，最大值100，默认为20(非必要参数)
        :param KeyWord:关键字，按照”%KeyWord%”模式搜索，不区分大小写(非必要参数)
        :param GroupId:域名分组ID，如果不填写则默认为全部分组(非必要参数)
        :return:
        """
        self.params['Action'] = 'DescribeDomains'
        self.params['PageNumber'] = PageNumber
        self.params['PageSize'] = PageSize
        self.params['KeyWord'] = KeyWord
        self.params['GroupId'] = GroupId
        self.params['Signature'] = Sign(self.AccessKeySecret).make(self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def get_domain_info(self, domain_name):
        """
        获取域名信息,
        :param domain_name: 域名
        :return: 获取域名信息（类型：字典）
        """
        self.params['Action'] = 'DescribeDomainInfo'
        self.params['DomainName'] = domain_name
        self.params['Signature'] = Sign(self.AccessKeySecret).make(self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def get_main_domain(self, InputString):
        """
        通过完成记录名获取主域名名称
        :param InputString: 完成的记录名，如 www.abc.com
        :return: 主域名名称
        """
        self.params['Action'] = 'GetMainDomainName'
        self.params['InputString'] = InputString
        self.params['Signature'] = Sign(self.AccessKeySecret).make(self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def get_domain_log(self, PageNumber='1', PageSize='100', KeyWord='' ):
        """
        获取域名操作日志
        :param PageNumber: 当前页数，起始值为1，默认为1 (非必要参数)
        :param PageSize: 分页查询时设置的每页行数，最大值100，默认为20 (非必要参数)
        :param KeyWord: 关键字，按照”%KeyWord%”模式搜索，不区分大小写 (非必要参数)
        :return:
        """
        self.params['Action'] = 'DescribeDomainLogs'
        self.params['PageNumber'] = PageNumber
        self.params['PageSize'] =  PageSize
        self.params['KeyWord'] =   KeyWord
        self.params['Signature'] = Sign(self.AccessKeySecret).make(self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)


    def get_record_list(self, DomainName, PageNumber='1', PageSize='500', RRKeyWord='', TypeKeyWord='', ValueKeyWord=''):
        """
        获取解析记录列表
        :param DomainName: 域名
        :param PageNumber: 当前页数，起始值为1，默认为1(非必要参数)
        :param PageSize: 分页查询时设置的每页行数，最大值500，默认为20 (非必要参数)
        :param RRKeyWord: 主机记录的关键字，按照”%RRKeyWord%”模式搜索，不区分大小写 (非必要参数)
        :param TypeKeyWord: 解析类型的关键字，按照全匹配搜索，不区分大小写 (非必要参数)
        :param ValueKeyWord: 记录值的关键字，按照”%ValueKeyWord%”模式搜索，不区分大小写(非必要参数)
        :return:
        """
        self.params['Action'] = 'DescribeDomainRecords'
        self.params['DomainName'] = DomainName
        self.params['PageNumber'] =PageNumber
        self.params['PageSize'] = PageSize
        self.params['RRKeyWord'] = RRKeyWord
        self.params['TypeKeyWord'] = TypeKeyWord
        self.params['ValueKeyWord'] = ValueKeyWord
        self.params['Signature'] = Sign(self.AccessKeySecret).make(self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def add_domain_record(self, DomainName, RR, Type, Value, TTL='600', Priority='1,', Line='default'):
        """
        添加解析记录
        参考文档：https://help.aliyun.com/document_detail/29772.html?spm=a2c4g.11186623.6.641.23b67becfWhKJS
        :param DomainName:域名名称(必填)
        :param RR:主机记录，如果要解析@.exmaple.com，主机记录要填写"@”，而不是空(必填)
        :param Type:解析记录类型，参见解析记录类型格式(必填)
        :param Value:记录值(必填)
        :param TTL:生存时间，默认为600秒（10分钟），参见TTL定义说明(非必填)
        :param Priority:MX记录的优先级，取值范围[1,10]，记录类型为MX记录时，此参数必须(非必填)
        :param Line:解析线路，默认为default。参见解析线路枚举(非必填)
        :return:
        """
        self.params['Action'] = 'AddDomainRecord'
        self.params['DomainName'] = DomainName
        self.params['RR'] = RR
        self.params['Type'] = Type
        self.params['Value'] = Value
        self.params['TTL'] = TTL
        if Type.upper() == 'MX':
            self.params['Priority'] = Priority
        self.params['Line'] = Line
        self.params['Signature'] = Sign(self.AccessKeySecret).make(self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def delete_domain_record(self, RecordId):
        """
        删除解析记录
        :param RecordId:解析记录的ID，此参数在添加解析时会返回，在获取域名解析列表时会返回
        :return:
        """
        self.params['Action'] = 'DeleteDomainRecord'
        self.params['RecordId'] = str(RecordId)
        self.params['Signature'] = Sign(self.AccessKeySecret).make(self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def update_domain_record(self, RecordId, RR, Type, Value, TTL='600', Priority='1', Line='default'):
        """
        修改解析记录
        :param RecordId:解析记录的ID，此参数在添加解析时会返回，在获取域名解析列表时会返回
        :param RR:主机记录，如果要解析@.exmaple.com，主机记录要填写"@”，而不是空
        :param Type:解析记录类型，参见解析记录类型格式
        :param Value:记录值
        :param TTL:生存时间，默认为600秒（10分钟），参见TTL定义说明
        :param Priority:MX记录的优先级，取值范围[1,10]，记录类型为MX记录时，此参数必须
        :param Line:解析线路，默认为default。参见解析线路枚举
        :return:
        """
        self.params['Action'] = 'UpdateDomainRecord'
        self.params['RecordId'] = str(RecordId)
        self.params['RR'] = RR
        self.params['Type'] = Type
        self.params['Value'] = Value
        self.params['TTL'] = TTL
        if Type.upper() == 'MX':
            self.params['Priority'] = Priority
        self.params['Line'] = Line
        self.params['Signature'] = Sign(self.AccessKeySecret).make(self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)



if __name__ == '__main__':
    # 获取域名列表
    domains = DnsHelper().get_domain_list()

    # 打印每个域名下的解析记录
    for domain in domains['Domains']['Domain']:
        records = DnsHelper().get_record_list(domain['DomainName'])
        print(records)

    # # 指印域名操作日志
    # print(DnsHelper().get_domain_log())

    # 添加解析记录
    # a_record = {'DomainName': 'xx.com', 'RR':'alitest2', 'Type':'A', 'Value':'10.100.16.218'}
    # print( DnsHelper().add_domain_record(**a_record) )

    # # 更新解析记录
    # a_record = {'RecordId': '16687066160641024', 'RR':'alitest', 'Type':'A', 'Value':'10.100.16.30'}
    # print(DnsHelper().update_domain_record(**a_record))

    # 删除解析记录
    # print(DnsHelper().delete_domain_record(16687091176715264))