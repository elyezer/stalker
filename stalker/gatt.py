"""
All GATT commands have the following format:

Name￼| Size (octets)￼| Description
Opcode | 2 | PDU | operation code
connectionHandle | 2 | Connection Handle of link
Command | PDU Variable | Command parameters

Note: The connection handle of 0xFFFE is considered as the loopback connection.
All messages sent to this connection will be loop backed to the local host.

For the command parameters, please see the corresponding section below.

Event(s) Generated:

When a GATT command is received, the host will send the Command Status Event
with the Status parameter.

Return Parameters:

Status: (1 octet)

| Value | Parameter Description |
| 0x00 | SUCCESS |
| 0x02 | INVALIDPARAMETER |
| 0x04 | MSG_BUFFER_NOT_AVAIL|
| 0x13 | bleMemAllocError |
| 0x14 | bleNotConnected |
| 0x40 | bleInvalidPDU |
"""
from stalker.bluetooth import Command, Event


class DiscCharsByUUID(Event):
    """
    This sub-procedure is used by a client to discover service characteristics
    on a server when only the service handle ranges are known and the
    characteristic UUID is known. The specific service may exist multiple times
    on a server. The characteristic being discovered is identified by the
    characteristic UUID.

    start_handle: First requested handle number
    end_handle: Last requested handle number
    char_type: 2 or 16 octet UUID
    """

    def __init__(self, connection_handle, start_handle, end_handle, char_type):
        fmt = 'HHH%ds' % len(char_type)
        super(DiscCharsByUUID, self).__init__(
            0xfd88, fmt, connection_handle, start_handle, end_handle, char_type)

    @classmethod
    def parse(cls, data):
        return cls()
