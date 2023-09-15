import functools
import Queue as queue
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


EVENTS = {
    0x0600: 'GAP_DeviceInitDone',
    0x0601: 'GAP_DeviceDiscovery',
    0x0602: 'GAP_AdvertDataUpdateDone',
    0x0603: 'GAP_MakeDiscoverableDone',
    0x0604: 'GAP_EndDiscoverableDone',
    0x0605: 'GAP_LinkEstablished',
    0x0606: 'GAP_LinkTerminated',
    0x0607: 'GAP_LinkParamUpdate',
    0x0608: 'GAP_RandomAddrChanged',
    0x0609: 'GAP_SignatureUpdated',
    0x060a: 'GAP_AuthenticationComplete',
    0x060b: 'GAP_PasskeyNeeded',
    0x060c: 'GAP_SlaveRequestedSecurity',
    0x060d: 'GAP_DeviceInformation',
    0x060e: 'GAP_BondComplete',
    0x060f: 'GAP_PairingRequested',
    0x067f: 'CommandStatus',
}


ATT_EVENT_STATUS = {
    0x00: 'Success',
    0x14: 'BLENotConnected',
    0x17: 'BLETimeout',
    0x1a: 'BLEProcedureComplete',
}


IO_TIMEOUT = 2


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


class Command(Packet):
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


class Event(Packet):
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


def command(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        packet = f(*args, **kwargs)

        if isinstance(args[0], BluetoothDevice):
            args[0].packet_queue.put(packet)

        return packet
    return wrapper


class BluetoothDevice(object):
    def __init__(self, port=None, baudrate=57600):
        self.ready = False
        self.serial = serial.Serial(port, baudrate, timeout=IO_TIMEOUT)
        self.packet_queue = queue.Queue()

    @command
    def init_device(self, profile_role=0x08, max_scan_responses=0x03,
                    irk='\x00', csrk='\x00', sign_counter=0x01):
        """
        GAP_DeviceInit

        Parameters:
            profile_role:
                0x01 GAP_PROFILE_BROADCASTER
                0x02 GAP_PROFILE_OBSERVER
                0x04 GAP_PROFILE_PERIPHERAL
                0x08 GAP_PROFILE_CENTRAL
            max_scan_responses:
                0 – 0xFF Central or Observer only: The device will allocate
                buffer space for received advertisement packets. The
                default is 3. The larger the number, the more RAM that
                is needed and maintained.
            IRK:
                16 byte Identity Resolving Key (IRK). If this value is all 0’s,
                the GAP will randomly generate all 16 bytes. This key is used
                to generate Resolvable Private Addresses.
            CSRK:
                16 byte Connection Signature Resolving Key (CSRK). If this
                value is all 0’s, the GAP will randomly generate all 16 bytes.
                This key is used to generate data Signatures.
            sign_counter:
                0x00000000 – 0xffffffff 32 bit Signature Counter. Initial
                signature counter.

        Return Parameters:
            0x00 SUCCESS
            0x02 INVALIDPARAMETER
        """
        return Command(0xfe00, 'BB16s16sL', profile_role, max_scan_responses,
                       irk, csrk, sign_counter)

    @command
    def discovery(self, mode=3, active_scan=1, white_list=0):
        """
        GAP_DeviceDiscoveryRequest

        Parameters:
            mode:
                0 Non-Discoverable Scan
                1 General Mode Scan
                2 Limited Mode Scan
                3 Scan for all devices
            active_scan:
                0 Turn off active scanning (SCAN_REQ)
                1 Turn on active scanning (SCAN_REQ)
            white_list:
                0 Don't use the white list during a scan
                1 Use the white list during a scan

        Return Parameters:
            0x00 Success
            0x11 Scan is not available.
            0x12 Invalid profile role.
        """
        return Command(0xfe04, 'BBB', mode, active_scan, white_list)

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

        self.init_device()

    def stop(self):
        self.alive = False

    def join(self, transmit_only=False):
        self.transmitter_thread.join()
        if not transmit_only:
            self.receiver_thread.join()

    def reader(self):
        try:
            while self.alive and self._reader_alive:
                data = self.serial.read()

                if not data:
                    continue

                packet_type = struct.unpack('<B', data)[0]

                if packet_type == Event.packet_type:
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
        try:
            while self.alive:
                try:
                    packet = self.packet_queue.get(timeout=IO_TIMEOUT)
                    self.serial.write(packet.serialize())
                except queue.Empty:
                    pass
        except:
            self.alive = False
            raise
