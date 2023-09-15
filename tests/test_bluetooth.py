import unittest

from stalker.bluetooth import CommandPacket


class CommandPacketTestCase(unittest.TestCase):
    def test_command_packet_from_data(self):
        data = '\x01'
        packet = CommandPacket.from_data(data)
