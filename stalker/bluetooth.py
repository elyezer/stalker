import serial
import struct
import threading


BLUETOOTH_EVENTS = {
    0x05: 'Disconnection Complete',
    0x08: 'Encryption Change',
    0x0c: 'Read Remote Version Information Complete',
    0x0e: 'Command Complete',
    0x0f: 'Command Status',
    0x10: 'Hardware Error (optional)',
    0x13: 'Number Of Completed Packets',
    0x1a: 'Data Buffer Overflow',
    0x30: 'Encryption Key Refresh Complete',
}


BLUETOOTH_LE_EVENTS = {
    0x01: 'LE Connection Complete',
    0x02: 'LE Advertising Report',
    0x03: 'LE Connection Update Complete',
    0x04: 'LE Read Remote Used Features Complete',
    0x05: 'LE Long Term Key Requested',
}


class Packet(object):
    packet_type = None

    @classmethod
    def from_data(cls, data):
        if cls is Packet:
            raise TypeError('from_data should be called on Packet subclass')

        packet_type = struct.unpack('B', data[0])[0]

        if packet_type == cls.packet_type:
            return cls.parse(data[1:])
        else:
            raise TypeError('This is not a %s' % cls.__name__)

    @classmethod
    def parse(cls, data):
        raise NotImplementedError('A generic Packer could not be parsed')


class CommandPacket(Packet):
    packet_type = 1

    def __init__(self, opcode=None, fmt=None, *params):
        self.opcode = opcode
        self.fmt = fmt
        self.params = params

    @classmethod
    def parse(cls, data):
        return cls()

    def serialize(self):
        fmt = '<BHB%s' % self.fmt
        size = struct.calcsize('<%s' % self.fmt)
        return struct.pack(
            fmt, self.packet_type, self.opcode, size, *self.params)


class EventPacket(Packet):
    packet_type = 4

    def __init__(self, code=None, fmt=None, *params):
        self.code = code
        self.fmt = fmt
        self.params = params

    @classmethod
    def parse(cls, data):
        return cls()

    def serialize(self):
        fmt = '<BB%s' % self.fmt
        size = struct.calcsize('<%s' % self.fmt)
        return struct.pack(
            fmt, self.packet_type, self.code, size, *self.params)


class BluetoothDevice(object):
    def __init__(self, port=None, baudrate=57600):
        self.ready = False
        self.serial = serial.Serial(port, baudrate)

    def init_device(self):
        packet = CommandPacket(0xFE00, 'BB16s16sL', 8, 3, '\x00', '\x00', 1)
        self.serial.write(packet.serialize())

    def _start_reader(self):
        self._reader_alive = True
        self.receiver_thread = threading.Thread(target=self.reader)
        self.receiver_thread.setDaemon(True)
        self.receiver_thread.start()

    def _stop_reader(self):
        self._reader_alive = False
        self.receiver_thread.join()

    def start(self):
        self.alive = True
        self._start_reader()
        self.transmitter_thread = threading.Thread(target=self.writer)
        self.transmitter_thread.setDaemon(True)
        self.transmitter_thread.start()

    def stop(self):
        self.alive = False

    def join(self, transmit_only=False):
        self.transmitter_thread.join()
        if not transmit_only:
            self.receiver_thread.join()

    def reader(self):
        try:
            while self.alive and self._reader_alive:
                data = self.serial.read(1)
                packet_type = struct.unpack('<B', data)[0]

                if packet_type == EventPacket.packet_type:
                    event_code, params_len = struct.unpack(
                        '<BB', self.serial.read(2))
                    params_data = self.serial.read(params_len)

                    if event_code == 0xff:
                        print 'Vendor specific event'
                    elif event_code in BLUETOOTH_EVENTS:
                        event = BLUETOOTH_EVENTS[event_code]
                        print 'Bluetooth event "%s"' % event
                    elif event_code == 0x3e:
                        sub_event_code = struct.unpack('<B', params_data[0])[0]
                        event = BLUETOOTH_LE_EVENTS[sub_event_code]
                        print 'Bluetooth LE event "%s"' % event
                    else:
                        print 'Unknown event code %02x' % event_code
                else:
                    print 'wrong packet type %02x' % packet_type
        except serial.SerialException:
            self.alive = False
            raise

    def writer(self):
        pass
