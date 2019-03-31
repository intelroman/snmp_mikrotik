#!/usr/bin/python3
"""
Bulk walk Agent MIB (SNMPv2c)
+++++++++++++++++++++++++++++

Perform SNMP GETBULK operation with the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for OID in tuple form
* with non-repeaters=0 and max-repeaters=25

This script performs similar to the following Net-SNMP command:

| $ snmpbulkwalk -v2c -c public -ObentU -Cn0 -Cr25 demo.snmplabs.com 1.3.6

"""
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp
from pyasn1.codec.ber import encoder, decoder
from pysnmp.proto.api import v2c
from time import time

import os
from pprint import pprint as pp
from influxdb import InfluxDBClient
from config import *

client = InfluxDBClient(host=host, port=8086, username=username, password=password)
client.switch_database(DB)

date = os.popen("date +%s").read().split('\n')
t = ((int(date[0])) * 1000000000 - 10000000000)
hn = os.popen("hostname").read().split('\n')
data = {}

# SNMP table header
headVars = [v2c.ObjectIdentifier((1, 3, 6))]

# Build PDU
reqPDU = v2c.GetBulkRequestPDU()
v2c.apiBulkPDU.setDefaults(reqPDU)
v2c.apiBulkPDU.setNonRepeaters(reqPDU, 0)
v2c.apiBulkPDU.setMaxRepetitions(reqPDU, 25)
v2c.apiBulkPDU.setVarBinds(reqPDU, [(x, v2c.null) for x in headVars])

# Build message
reqMsg = v2c.Message()
v2c.apiMessage.setDefaults(reqMsg)
v2c.apiMessage.setCommunity(reqMsg, SNMP_COMMUNITY)
v2c.apiMessage.setPDU(reqMsg, reqPDU)

startedAt = time()


def cbTimerFun(timeNow):
    if timeNow - startedAt > 3:
        raise Exception("Request timed out")


# noinspection PyUnusedLocal
def cbRecvFun(transportDispatcher, transportDomain, transportAddress,
              wholeMsg, reqPDU=reqPDU, headVars=headVars):
    while wholeMsg:
        rspMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=v2c.Message())

        rspPDU = v2c.apiMessage.getPDU(rspMsg)

        # Match response to request
        if v2c.apiBulkPDU.getRequestID(reqPDU) == v2c.apiBulkPDU.getRequestID(rspPDU):
            # Format var-binds table
            varBindTable = v2c.apiBulkPDU.getVarBindTable(reqPDU, rspPDU)

            # Check for SNMP errors reported
            errorStatus = v2c.apiBulkPDU.getErrorStatus(rspPDU)
            if errorStatus and errorStatus != 2:
                errorIndex = v2c.apiBulkPDU.getErrorIndex(rspPDU)
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBindTable[int(errorIndex) - 1] or '?'))
                transportDispatcher.jobFinished(1)
                break

            # Report SNMP table
            for tableRow in varBindTable:
                for name, val in tableRow:
#                   print('from: %s, %s = %s' % (
#                        transportAddress, name.prettyPrint(), val.prettyPrint()
#                    )
#                          )
                    data.update({ (name.prettyPrint()) : (val.prettyPrint())})

            # Stop on EOM
            for oid, val in varBindTable[-1]:
                if not isinstance(val, v2c.Null):
                    break
            else:
                transportDispatcher.jobFinished(1)

            # Generate request for next row
            v2c.apiBulkPDU.setVarBinds(
                reqPDU, [(x, v2c.null) for x, y in varBindTable[-1]]
            )
            v2c.apiBulkPDU.setRequestID(reqPDU, v2c.getNextRequestID())
            transportDispatcher.sendMessage(
                encoder.encode(reqMsg), transportDomain, transportAddress
            )
            global startedAt
            if time() - startedAt > 3:
                raise Exception('Request timed out')
            startedAt = time()
    return wholeMsg


transportDispatcher = AsyncoreDispatcher()

transportDispatcher.registerRecvCbFun(cbRecvFun)
transportDispatcher.registerTimerCbFun(cbTimerFun)

transportDispatcher.registerTransport(
    udp.domainName, udp.UdpSocketTransport().openClientMode()
)
transportDispatcher.sendMessage(
    encoder.encode(reqMsg), udp.domainName, (SNMP_HOST, 161)
)
transportDispatcher.jobStarted(1)

# Dispatcher will finish as job#1 counter reaches zero
transportDispatcher.runDispatcher()

transportDispatcher.closeDispatcher()

ifindex = []
if_stats = {}
for i in data.keys():
    if '1.3.6.1.2.1.2.2.1.2.' in i:
        ifindex.append(i.split('.')[-1])
for i in ifindex:
    if_stats.update({data["1.3.6.1.2.1.2.2.1.2.%s" % (i)]:{
                                    "devName": data['1.3.6.1.2.1.1.5.0'],
                                    "ifindex": data['1.3.6.1.2.1.2.2.1.1.%s' % (i)],
                                    "ifInOctets": data['1.3.6.1.2.1.2.2.1.10.%s' % (i)],
                                    "ifInUcastPkts": data['1.3.6.1.2.1.2.2.1.11.%s' % (i)],
                                    "ifInNUcastPkts": data['1.3.6.1.2.1.2.2.1.12.%s' % (i)],
                                    "ifInDiscards": data['1.3.6.1.2.1.2.2.1.13.%s' % (i)],
                                    "ifInErrors": data['1.3.6.1.2.1.2.2.1.14.%s' % (i)],
                                    "ifInUnknownPorts": data['1.3.6.1.2.1.2.2.1.15.%s' % (i)],
                                    "ifOutOctets": data['1.3.6.1.2.1.2.2.1.16.%s' % (i)],
                                    "ifOutUcastPkts": data['1.3.6.1.2.1.2.2.1.17.%s' % (i)],
                                    "ifOutNUcastPkts": data['1.3.6.1.2.1.2.2.1.18.%s' % (i)],
                                    "ifOutDiscards": data['1.3.6.1.2.1.2.2.1.19.%s' % (i)],
                                    "ifDescr": data['1.3.6.1.2.1.2.2.1.2.%s' % (i)],
                                    "ifOutErrors": data['1.3.6.1.2.1.2.2.1.20.%s' % (i)],
                                    "ifOutQLen": data['1.3.6.1.2.1.2.2.1.21.%s' % (i)],
                                    "ifSpecific": data['1.3.6.1.2.1.2.2.1.22.%s' % (i)],
                                    "ifType": data['1.3.6.1.2.1.2.2.1.3.%s' % (i)],
                                    "ifMTU": data['1.3.6.1.2.1.2.2.1.4.%s' % (i)],
                                    "ifSpeed": data['1.3.6.1.2.1.2.2.1.5.%s' % (i)],
                                    "ifPhyAddress": data['1.3.6.1.2.1.2.2.1.6.%s' % (i)],
                                    "ifAdminStatus": data['1.3.6.1.2.1.2.2.1.7.%s' % (i)],
                                    "ifOperStatus": data['1.3.6.1.2.1.2.2.1.8.%s' % (i)],
                                    "bytes-in": data['1.3.6.1.2.1.31.1.1.1.6.%s' % (i)], 
                                    "packets-in": data['1.3.6.1.2.1.31.1.1.1.7.%s' % (i)],
                                    "bytes-out": data['1.3.6.1.2.1.31.1.1.1.10.%s' % (i)],
                                    "packets-out": data['1.3.6.1.2.1.31.1.1.1.11.%s' % (i)],
                                    "ifLastChange": data['1.3.6.1.2.1.2.2.1.9.%s' % (i)]
                                    }
                                    })

influx_int = []
for i in if_stats.keys():
    influx_int.append({
                        "measurement": "snmp",
                        "tags": {
                                 "devName": if_stats[i]['devName'],
                                 "ifindex": if_stats[i]['ifindex'],
                                 "ifDescr": if_stats[i]['ifDescr'],
                                 "ifType": if_stats[i]['ifType'],
                                 "ifMTU": if_stats[i]['ifMTU'],
                                 "ifSpeed": if_stats[i]['ifSpeed'],
                                 "ifAdminStatus": if_stats[i]['ifAdminStatus'],
                                 "ifOperStatus": if_stats[i]['ifOperStatus']
                                },
                        "time": t,
                        "fields": {
                                   "ifInUcastPkts": int(if_stats[i]['ifInUcastPkts']),
                                   "ifInNUcastPkts": int(if_stats[i]['ifInNUcastPkts']),
                                   "ifInDiscards": int(if_stats[i]['ifInDiscards']),
                                   "ifInErrors": int(if_stats[i]['ifInErrors']),
                                   "ifInUnknownPorts": int(if_stats[i]['ifInUnknownPorts']),
                                   "ifOutUcastPkts": int(if_stats[i]['ifOutUcastPkts']),
                                   "ifOutNUcastPkts": int(if_stats[i]['ifOutNUcastPkts']),
                                   "ifOutDiscards": int(if_stats[i]['ifOutDiscards']),
                                   "ifOutErrors": int(if_stats[i]['ifOutErrors']),
                                   "bytes-in": int(if_stats[i]['bytes-in']), 
                                   "packets-in": int(if_stats[i]['packets-in']),
                                   "bytes-out": int(if_stats[i]['bytes-out']),
                                   "packets-out": int(if_stats[i]['packets-out']),
                                   "ifOutQLen": int(if_stats[i]['ifOutQLen'])
                                  }
                        }
                        )
client.write_points(influx_int)
