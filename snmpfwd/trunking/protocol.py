from pyasn1.type import univ, tag, constraint, namedtype, namedval
from pyasn1.codec.ber import encoder, decoder
from pyasn1.error import SubstrateUnderrunError
from pysnmp.proto import rfc1905
from snmpfwd.trunking import crypto

class Message(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(0)),
        namedtype.NamedType('msg-id', univ.Integer()),
        namedtype.NamedType('content-id', univ.Integer(namedValues=namedval.NamedValues(('request', 0), ('response', 1), ('announcement', 2)))),
        namedtype.NamedType('payload', univ.OctetString())
    )

class Request(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('snmp-engine-id', univ.OctetString()),
        namedtype.NamedType('snmp-transport-domain', univ.ObjectIdentifier()),
        namedtype.NamedType('snmp-peer-address', univ.OctetString()),
        namedtype.NamedType('snmp-peer-port', univ.Integer()),
        namedtype.NamedType('snmp-bind-address', univ.OctetString()),
        namedtype.NamedType('snmp-bind-port', univ.Integer()),
        namedtype.NamedType('snmp-security-model', univ.Integer()),
        namedtype.NamedType('snmp-security-level', univ.Integer()),
        namedtype.NamedType('snmp-security-name', univ.OctetString()),
        namedtype.NamedType('snmp-context-engine-id', univ.OctetString()),
        namedtype.NamedType('snmp-context-name', univ.OctetString()),
        namedtype.NamedType('snmp-pdu', univ.OctetString())
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

pduMap = {
    0: Request(),
    1: Response(),
    2: Announcement()
}

def prepareRequestData(msgId, req, secret):
    r = Request()
    for k in 'snmp-engine-id', \
             'snmp-transport-domain', \
             'snmp-peer-address', 'snmp-peer-port', \
             'snmp-bind-address', 'snmp-bind-port', \
             'snmp-security-model', 'snmp-security-level', \
             'snmp-security-name', 'snmp-context-engine-id', \
             'snmp-context-name':
        r[k] = req[k]

    r['snmp-pdu'] = encoder.encode(req['snmp-pdu'])

    msg = Message()
    msg['version'] = 0
    msg['msg-id'] = msgId
    msg['content-id'] = 'request'
    msg['payload'] = crypto.encrypt(secret, encoder.encode(r))
        
    return encoder.encode(msg)

def prepareResponseData(msgId, rsp, secret):
    r = Response()
    r['error-indication'] = rsp.get('error-indication', '')
    r['snmp-pdu'] = rsp['snmp-pdu'] and encoder.encode(rsp['snmp-pdu']) or ''

    msg = Message()
    msg['version'] = 0
    msg['msg-id'] = msgId
    msg['content-id'] = 'response'
    msg['payload'] = crypto.encrypt(secret, encoder.encode(r))
        
    return encoder.encode(msg)

def prepareAnnouncementData(trunkId, secret):
    r = Announcement()
    r['trunk-id'] = trunkId

    msg = Message()
    msg['version'] = 0
    msg['msg-id'] = 0
    msg['content-id'] = 'announcement'
    msg['payload'] = crypto.encrypt(secret, encoder.encode(r))
        
    return encoder.encode(msg)

def prepareDataElements(octets, secret):
    try:
        msg, octets = decoder.decode(octets, asn1Spec=Message())
    except SubstrateUnderrunError:
        return None, None, None, octets

    if msg['version'] > 0:
        raise SnmpfwdError('Unsupported protocol version: %s' % msg['version'])

    r, _ = decoder.decode(
        crypto.decrypt(secret, msg['payload'].asOctets()),
        asn1Spec=pduMap.get(msg['content-id'])
    )

    rsp = {}

    if msg['content-id'] == 0:     # request
        for k in 'snmp-engine-id', \
                 'snmp-transport-domain', \
                 'snmp-peer-address', 'snmp-peer-port', \
                 'snmp-bind-address', 'snmp-bind-port', \
                 'snmp-security-model', 'snmp-security-level', \
                 'snmp-security-name', \
                 'snmp-context-engine-id', 'snmp-context-name':
            rsp[k] = r[k]

        rsp['snmp-pdu'], _ = decoder.decode(r['snmp-pdu'],
                                            asn1Spec=rfc1905.PDUs())
    elif msg['content-id'] == 1:   # response
        rsp['error-indication'] = r['error-indication']
        if not r['error-indication']:
            rsp['snmp-pdu'], _ = decoder.decode(r['snmp-pdu'],
                                                asn1Spec=rfc1905.PDUs())
    elif msg['content-id'] == 2:   # announcement
        rsp['trunk-id'] = r['trunk-id']
        
    if 'snmp-pdu' in rsp:
        rsp['snmp-pdu'] = rsp['snmp-pdu'].getComponent()

    return msg['msg-id'], msg['content-id'], rsp, octets
