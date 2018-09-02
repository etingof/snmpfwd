#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
from pyasn1.type import univ, namedtype, namedval
from pyasn1.codec.ber import encoder, decoder
from pyasn1.error import SubstrateUnderrunError
from pysnmp.proto import rfc1905
from snmpfwd.trunking import crypto
from snmpfwd.error import SnmpfwdError

PROTOCOL_VERSION = 3

MSG_TYPE_REQUEST = 0
MSG_TYPE_RESPONSE = 1
MSG_TYPE_ANNOUNCEMENT = 2
MSG_TYPE_PING = 3
MSG_TYPE_PONG = 4


class Message(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('msg-id', univ.Integer()),
        namedtype.NamedType('content-id', univ.Integer(namedValues=namedval.NamedValues(('request', MSG_TYPE_REQUEST), ('response', MSG_TYPE_RESPONSE), ('announcement', MSG_TYPE_ANNOUNCEMENT), ('ping', MSG_TYPE_PING), ('pong', MSG_TYPE_PONG)))),
        namedtype.NamedType('payload', univ.OctetString())
    )


class Request(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('callflow-id', univ.OctetString()),
        # SNMP details
        namedtype.NamedType('snmp-engine-id', univ.OctetString()),
        namedtype.NamedType('snmp-transport-domain', univ.ObjectIdentifier()),
        namedtype.NamedType('snmp-peer-address', univ.OctetString()),
        namedtype.NamedType('snmp-peer-port', univ.Integer()),
        namedtype.NamedType('snmp-bind-address', univ.OctetString()),
        namedtype.NamedType('snmp-bind-port', univ.Integer()),
        namedtype.NamedType('snmp-security-model', univ.Integer()),
        namedtype.NamedType('snmp-security-level', univ.Integer()),
        namedtype.NamedType('snmp-security-name', univ.OctetString()),
        namedtype.NamedType('snmp-security-engine-id', univ.OctetString()),
        namedtype.NamedType('snmp-context-engine-id', univ.OctetString()),
        namedtype.NamedType('snmp-context-name', univ.OctetString()),
        namedtype.NamedType('snmp-pdu', univ.OctetString()),
        # server classifiers
        namedtype.NamedType('snmp-credentials-id', univ.OctetString('')),
        namedtype.NamedType('snmp-context-id', univ.OctetString('')),
        namedtype.NamedType('snmp-content-id', univ.OctetString('')),
        namedtype.NamedType('snmp-peer-id', univ.OctetString('')),
    )


class Response(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('error-indication', univ.OctetString('')),
        namedtype.NamedType('snmp-pdu', univ.OctetString(''))
    )


class Announcement(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('trunk-id', univ.OctetString())
    )


class Ping(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('serial', univ.Integer())
    )


class Pong(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('serial', univ.Integer())
    )


pduMap = {
    MSG_TYPE_REQUEST: Request(),
    MSG_TYPE_RESPONSE: Response(),
    MSG_TYPE_ANNOUNCEMENT: Announcement(),
    MSG_TYPE_PING: Ping(),
    MSG_TYPE_PONG: Pong(),
}


def prepareRequestData(msgId, req, secret):
    r = Request()

    r['callflow-id'] = req['callflow-id']

    for k in ('snmp-engine-id',
              'snmp-transport-domain',
              'snmp-peer-address',
              'snmp-peer-port',
              'snmp-bind-address',
              'snmp-bind-port',
              'snmp-security-model',
              'snmp-security-level',
              'snmp-security-name',
              'snmp-security-engine-id',
              'snmp-context-engine-id',
              'snmp-context-name',
              'snmp-credentials-id',
              'snmp-context-id',
              'snmp-content-id',
              'snmp-peer-id'):
        r[k] = req[k]

    r['snmp-pdu'] = encoder.encode(req['snmp-pdu'])

    msg = Message()
    msg['version'] = PROTOCOL_VERSION
    msg['msg-id'] = msgId
    msg['content-id'] = 'request'

    if secret:
        msg['payload'] = crypto.encrypt(secret, encoder.encode(r))
    else:
        msg['payload'] = encoder.encode(r)

    return encoder.encode(msg)


def prepareResponseData(msgId, rsp, secret):
    r = Response()
    r['error-indication'] = str(rsp.get('error-indication', ''))
    r['snmp-pdu'] = rsp['snmp-pdu'] and encoder.encode(rsp['snmp-pdu']) or ''

    msg = Message()
    msg['version'] = PROTOCOL_VERSION
    msg['msg-id'] = msgId
    msg['content-id'] = 'response'
    msg['payload'] = encoder.encode(r)
    if secret:
        msg['payload'] = crypto.encrypt(secret, encoder.encode(r))
    else:
        msg['payload'] = encoder.encode(r)
    return encoder.encode(msg)


def prepareAnnouncementData(trunkId, secret):
    r = Announcement()
    r['trunk-id'] = trunkId

    msg = Message()
    msg['version'] = PROTOCOL_VERSION
    msg['msg-id'] = 0
    msg['content-id'] = 'announcement'
    msg['payload'] = encoder.encode(r)
    if secret:
        msg['payload'] = crypto.encrypt(secret, encoder.encode(r))
    else:
        msg['payload'] = encoder.encode(r)
    return encoder.encode(msg)


def _preparePingPongData(reqType, msgId, serial, secret):
    msg = Message()
    msg['version'] = PROTOCOL_VERSION
    msg['msg-id'] = msgId
    msg['content-id'] = reqType

    if msg['content-id'] == MSG_TYPE_PING:
        r = Ping()
    elif msg['content-id'] == MSG_TYPE_PONG:
        r = Pong()
    else:
        raise SnmpfwdError('not a ping-pong message')

    r['serial'] = serial

    msg['payload'] = encoder.encode(r)
    if secret:
        msg['payload'] = crypto.encrypt(secret, encoder.encode(r))
    else:
        msg['payload'] = encoder.encode(r)
    return encoder.encode(msg)


def preparePingData(msgId, serial, secret):
    return _preparePingPongData(MSG_TYPE_PING, msgId, serial, secret)


def preparePongData(msgId, serial, secret):
    return _preparePingPongData(MSG_TYPE_PONG, msgId, serial, secret)


def prepareDataElements(octets, secret):
    try:
        msg, octets = decoder.decode(octets, asn1Spec=Message())

    except SubstrateUnderrunError:
        return None, None, None, octets

    if msg['version'] != PROTOCOL_VERSION:
        raise SnmpfwdError('Unsupported protocol versions %s/%s' % (msg['version'], PROTOCOL_VERSION))

    r, _ = decoder.decode(
        secret and crypto.decrypt(secret, msg['payload'].asOctets()) or msg['payload'].asOctets(),
        asn1Spec=pduMap.get(msg['content-id'])
    )

    rsp = {}

    if msg['content-id'] == MSG_TYPE_REQUEST:
        rsp['callflow-id'] = r['callflow-id']

        for k in ('snmp-engine-id',
                  'snmp-transport-domain',
                  'snmp-peer-address',
                  'snmp-peer-port',
                  'snmp-bind-address',
                  'snmp-bind-port',
                  'snmp-security-model',
                  'snmp-security-level',
                  'snmp-security-name',
                  'snmp-security-engine-id',
                  'snmp-context-engine-id',
                  'snmp-context-name',
                  'snmp-credentials-id',
                  'snmp-context-id',
                  'snmp-content-id',
                  'snmp-peer-id'):
            rsp[k] = r[k]

        pdu, _ = decoder.decode(r['snmp-pdu'], asn1Spec=rfc1905.PDUs())
        rsp['snmp-pdu'] = pdu.getComponent()

    elif msg['content-id'] == MSG_TYPE_RESPONSE:
        rsp['error-indication'] = r['error-indication']
        if not r['error-indication'] and r['snmp-pdu']:
            pdu, _ = decoder.decode(r['snmp-pdu'], asn1Spec=rfc1905.PDUs())
            rsp['snmp-pdu'] = pdu.getComponent()

    elif msg['content-id'] == MSG_TYPE_ANNOUNCEMENT:
        rsp['trunk-id'] = r['trunk-id']

    elif msg['content-id'] == MSG_TYPE_PING:
        rsp['serial'] = r['serial']

    elif msg['content-id'] == MSG_TYPE_PONG:
        rsp['serial'] = r['serial']

    return msg['msg-id'], msg['content-id'], rsp, octets
