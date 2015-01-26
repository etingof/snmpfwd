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
        namedtype.NamedType('engine-id', univ.OctetString()),
        namedtype.NamedType('transport-domain', univ.ObjectIdentifier()),
        namedtype.NamedType('transport-address', univ.OctetString()),
        namedtype.NamedType('security-model', univ.Integer()),
        namedtype.NamedType('security-level', univ.Integer()),
        namedtype.NamedType('security-name', univ.OctetString()),
        namedtype.NamedType('context-engine-id', univ.OctetString()),
        namedtype.NamedType('context-name', univ.OctetString()),
        namedtype.NamedType('pdu', univ.OctetString())
    )

class Response(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('error-indication', univ.OctetString('')),
        namedtype.NamedType('pdu', univ.OctetString(''))
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
    for k in 'engine-id', 'transport-domain', \
             'transport-address', 'security-model', 'security-level', \
             'security-name', 'context-engine-id', 'context-name':
        r[k] = req[k]

    r['pdu'] = encoder.encode(req['pdu'])

    msg = Message()
    msg['version'] = 0
    msg['msg-id'] = msgId
    msg['content-id'] = 'request'
    msg['payload'] = crypto.encrypt(secret, encoder.encode(r))
        
    return encoder.encode(msg)

def prepareResponseData(msgId, rsp, secret):
    r = Response()
    r['error-indication'] = rsp.get('error-indication', '')
    r['pdu'] = rsp['pdu'] and encoder.encode(rsp['pdu']) or ''

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
        for k in 'engine-id', 'transport-domain', \
                'transport-address', 'security-model', 'security-level', \
                'security-name', 'context-engine-id', 'context-name':
            rsp[k] = r[k]

        rsp['pdu'], _ = decoder.decode(r['pdu'], asn1Spec=rfc1905.PDUs())
    elif msg['content-id'] == 1:   # response
        rsp['error-indication'] = r['error-indication']
        if not r['error-indication']:
            rsp['pdu'], _ = decoder.decode(r['pdu'], asn1Spec=rfc1905.PDUs())
    elif msg['content-id'] == 2:   # announcement
        rsp['trunk-id'] = r['trunk-id']
        
    if 'pdu' in rsp:
        rsp['pdu'] = rsp['pdu'].getComponent()

    return msg['msg-id'], msg['content-id'], rsp, octets
