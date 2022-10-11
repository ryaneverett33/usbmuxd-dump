#!/usr/bin/env python3
import json
import os
import struct
import subprocess
from datetime import datetime, timedelta
import socket
import codecs
import os
import plistlib
import typing
import math

from frida_tools.application import ConsoleApplication
from pyasn1.codec.der import decoder


AGENT_FILENAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.js")

class UIDEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, plistlib.UID):
            # if the obj is uid, we simply return the str of the uid
            return str(obj)
        return json.JSONEncoder.default(self, obj)


class Application(ConsoleApplication):

    SESSION_ID_LENGTH = 32
    MASTER_KEY_LENGTH = 48
    # sessions[fd] = (<bytes sent by client>,
    #                 <bytes sent by server>)
    sessions = {}

    def _add_options(self, parser):
        parser.add_option("-o", "--output", help="usbmuxd pcap dump")
        parser.add_option("--tcpdump-output", dest="tcpdump_output", help="Dump traffic with tcpdump too")
        # parser.add_option("-k", "--keys", help="SSL keylog file to write")
        parser.add_option("-t", "--text", help="text dump file")
        parser.add_option("--dump-plists", dest="dump_plists", help="Dump plists to a specified directory")

    def _initialize(self, parser, options, args):
        defined_options = vars(options)
        if defined_options["output"] == None or defined_options["text"] == None or defined_options["tcpdump_output"] == None:
            print("Must pass -o/--output, -t/--text, and --tcpdump-output to specify dump files")
            exit(1)
        self.pcap_file = open(os.path.join(os.curdir, options.output), "wb")
        self.tcpdump_file = os.path.join(os.curdir, options.tcpdump_output)
        self.base_text_file = os.path.join(os.curdir, options.text)
        self.session_text_files = {}        # id -> file descriptor
        self.dump_dir = None
        self.next_dump_file = 0
        self.popen_instances = []
        self.first_timestamp = None

        if defined_options["dump_plists"] != None:
            self.dump_dir = os.path.join(os.curdir, options.dump_plists)
            if not os.path.exists(self.dump_dir):
                os.mkdir(self.dump_dir)
            files = os.listdir(self.dump_dir)
            for file in files:
                os.remove(os.path.join(self.dump_dir, file))

        codecs.register_error('replace_dash', lambda e: (u'-', e.start + 1))
        self.write_pcap_header()
        self.hijack_usbmuxd_socket()

    def _usage(self):
        return "usage: %prog [options] target"

    def _needs_target(self):
        return True
    
    def _stop(self):
        self.pcap_file.flush()
        self.pcap_file.close()
        for _,fd in self.session_text_files.items():
            fd.close()
        self.restore_usbmuxd_socket()

    def _start(self):
        self._update_status("Attached")

        def on_message(message, data):
            self._reactor.schedule(lambda: self._on_message(message, data))

        self._session_cache = set()

        self._script = self._session.create_script(self._agent())
        self._script.on("message", on_message)

        self._update_status("Loading script...")
        self._script.load()
        self._update_status("Loaded script")

    def _on_message(self, message, data):
        if message["payload"]["type"] in ["recv", "send"]:
            payload = message["payload"]
            fd = payload["fd"]
            if fd not in self.sessions:
                self.sessions[fd] = (0,0)
            
            client_sent, server_sent = self.sessions[fd]
            if payload["type"] == "recv":
                seq, ack = (server_sent, client_sent)
            else:
                seq, ack = (client_sent, server_sent)

            self.write_pcap(payload["message"],
                            payload["timestamp"],
                            payload["src"],
                            payload["dest"],
                            seq, ack)
            self.write_text(payload["message"],
                            payload["timestamp"],
                            payload["src"],
                            payload["dest"],
                            payload["type"],
                            fd)
            if payload["type"] == "recv":
                server_sent += len(payload["message"])
            else:
                client_sent += len(payload["message"])
            self.sessions[fd] = (client_sent, server_sent)

    def timestr(self, timestamp: typing.Union[datetime, timedelta]) -> str:
        if isinstance(timestamp, datetime):
            return timestamp.strftime('%H:%M:%S.%f')
        else:
            total_seconds = timestamp.total_seconds()
            hours, minutes = divmod(total_seconds, 3600)
            minutes, seconds = divmod(minutes, 60)
            milliseconds = math.modf(seconds)[0] * 1000
            return '{:02}:{:02}:{:02}.{:04}'.format(int(hours), int(minutes), int(seconds), int(milliseconds))

    def dump_plist_to_str(self, data_bytes: bytes, basic_decode: str) -> typing.Tuple[bool, str]:
        if "bplist" in basic_decode:
            try:
                bplist = plistlib.loads(data_bytes, fmt=plistlib.FMT_BINARY)
                bplist_bytes = plistlib.dumps(bplist, skipkeys=True)

                return (True, bplist_bytes.decode("ascii", 'replace_dash'))
            except TypeError:
                return (True, json.dumps(bplist, cls=UIDEncoder))
            except Exception:
                return (True, "Corrupted binary plist")
        return (False, basic_decode)

    def write_text(self, data, timestamp, src_info, dst_info, payload_type, session_id):
        # get text file for session
        if session_id not in self.session_text_files:
            self.session_text_files[session_id] = open(self.base_text_file + f".{session_id}", 'w')
        text_file = self.session_text_files[session_id]

        time = datetime.fromtimestamp(timestamp / 1000)
        time = self.get_relative_timestamp(time)
        time_str = self.timestr(time)
        src_info["address"] = socket.inet_ntop(socket.AF_INET, struct.pack(">I", src_info['address']))
        src_info["port"] = socket.htons(src_info["port"])
        dst_info["address"] = socket.inet_ntop(socket.AF_INET, struct.pack(">I", dst_info['address']))
        dst_info["port"] = socket.htons(dst_info["port"])

        text_file.write(f"[{time_str}] {src_info['address']}:{src_info['port']} -> {dst_info['address']}:{dst_info['port']} [{payload_type}]\n")
        data_bytes = bytes(data)
        decoded_data = data_bytes.decode("ascii", 'replace_dash')
        if "plist" in decoded_data:
            is_bplist, plist_str = self.dump_plist_to_str(data_bytes, decoded_data)
            if self.dump_dir is not None:
                plist_file_name = f"{self.next_dump_file}.plist"
                text_file.write(f"[{plist_file_name}]\n")
                plist_str_lines = plist_str.split('\n')[0:20]            # print the first 20 lines
                text_file.write('\n'.join(plist_str_lines) + '\n')

                with open(os.path.join(self.dump_dir, plist_file_name), 'wb') as plist_file:
                    plist_file.write(data_bytes)
                self.next_dump_file += 1
            else:
                text_file.write("[BPLIST]" if is_bplist else "[PLIST]\n")
                text_file.write(plist_str)

        text_file.write('\n')
        text_file.flush()

    def write_pcap(self, data, timestamp, src_info, dst_info, seq, ack):
        time = datetime.fromtimestamp(timestamp / 1000)
        try:
            # src_info["address"] = socket.inet_ntop(socket.AF_INET, struct.pack(">I", src_info['address']))
            src_info["port"] = socket.htons(src_info["port"])
            # dst_info["address"] = socket.inet_ntop(socket.AF_INET, struct.pack(">I", dst_info['address']))
            dst_info["port"] = socket.htons(dst_info["port"])
            # print(f"Data size: {len(data)}")
            for writes in (
                # PCAP record (packet) header
                ("=I", time.second),                   # Timestamp seconds
                ("=I", time.microsecond),  # Timestamp microseconds
                ("=I", 40 + len(data)),           # Number of octets saved
                ("=i", 40 + len(data)),           # Actual length of packet
                # IPv4 header
                (">B", 0x45),                     # Version and Header Length
                (">B", 0),                        # Type of Service
                (">H", 40 + len(data)),           # Total Length
                (">H", 0),                        # Identification
                (">H", 0x4000),                   # Flags and Fragment Offset
                (">B", 0xFF),                     # Time to Live
                (">B", 6),                        # Protocol
                (">H", 0),                        # Header Checksum
                (">I", src_info["address"]),                 # Source Address
                (">I", dst_info["address"]),                 # Destination Address
                # TCP header
                (">H", src_info["port"]),                 # Source Port
                (">H", dst_info["port"]),                 # Destination Port
                (">I", seq),                      # Sequence Number
                (">I", ack),                      # Acknowledgment Number
                (">H", 0x5018),                   # Header Length and Flags
                (">H", 0xFFFF),                   # Window Size
                (">H", 0),                        # Checksum
                (">H", 0)):                       # Urgent Pointer
                self.pcap_file.write(struct.pack(writes[0], writes[1]))
            self.pcap_file.write(bytes(data))
            self.pcap_file.flush()
        except Exception:
            time_str = self.timestr(time)
            print(f"failed to write packet info at {time_str}")
    
    def write_pcap_header(self):
        for writes in (
            ("=I", 0xa1b2c3d4),     # Magic number
            ("=H", 2),              # Major version number
            ("=H", 4),              # Minor version number
            ("=I", 0),              # Reserved1
            ("=I", 0),              # Reserved2
            ("=I", 65535),          # Max length of captured packets
            ("=I", 228)):           # Data link type (LINKTYPE_IPV4)
            self.pcap_file.write(struct.pack(writes[0], writes[1]))
        self.pcap_file.flush()
    
    def get_relative_timestamp(self, timestamp: datetime):
        """Get the timestamp relative to when the first timestamp came in"""
        if self.first_timestamp is None:
            self.first_timestamp = timestamp
            return datetime.min
        else:
            return timestamp - self.first_timestamp

    def _on_session(self, data):
        asn1Sequence, _ = decoder.decode(data)

        session_id = asn1Sequence[3].asOctets()
        master_key = asn1Sequence[4].asOctets()

        self._keylog(session_id, master_key)

    def _cache_session(self, session_id):
        if session_id in self._session_cache:
            return False

        self._session_cache.add(session_id)
        return True

    def _keylog(self, session_id, master_key):
        # The hooks can catch the SSL session in an uninitialized state
        if not session_id:
            self._log("warning", "Uninitialized Session ID: {}".format(master_key.hex()))
            return False

        if not self._cache_session(session_id):
            return

        try:
            keylog_str = self._keylog_str(session_id, master_key)
        except ValueError as e:
            self._log("warning", "Ignored key log: {}".format(e))
            return

        self._log("info", "Logging SSL session: {}".format(keylog_str))
        self._write(keylog_str + "\n")

    @classmethod
    def _keylog_str(cls, session_id, master_key):
        if len(session_id) != cls.SESSION_ID_LENGTH:
            raise ValueError("Session ID length is incorrect")

        if len(master_key) != cls.MASTER_KEY_LENGTH:
            raise ValueError("Master Key length is incorrect")

        return "RSA Session-ID:{} Master-Key:{}".format(
            session_id.hex(),
            master_key.hex(),
        )

    @staticmethod
    def _agent():
        with open(AGENT_FILENAME) as f:
            return f.read()

    def hijack_usbmuxd_socket(self):
        print("--- Dumping /var/run/usbmuxd with tcpdump ---")
        # Rename the original socket
        cmd = "sudo mv /var/run/usbmuxd /var/run/usbmuxd.orig"
        print(cmd)
        subprocess.check_call(cmd, shell=True)

        # Open socat instances to perform redirection
        cmd = "sudo socat TCP-LISTEN:6000,reuseaddr,fork UNIX-CONNECT:/var/run/usbmuxd.orig"
        print(cmd)
        self.popen_instances.append(subprocess.Popen(cmd, shell=True))
        print(f"\tSpawned: {self.popen_instances[len(self.popen_instances) - 1].pid}")

        cmd = "sudo socat UNIX-LISTEN:/var/run/usbmuxd,fork,perm=0777 TCP-CONNECT:127.0.0.1:6000"
        print(cmd)
        self.popen_instances.append(subprocess.Popen(cmd, shell=True))
        print(f"\tSpawned: {self.popen_instances[len(self.popen_instances) - 1].pid}")

        # Start dumping with tcpdump
        cmd = f"sudo tcpdump -i lo0 -f 'tcp port 6000' -s 65535 -w {self.tcpdump_file}"
        print(cmd)
        self.popen_instances.append(subprocess.Popen(cmd, shell=True))
        print(f"\tSpawned: {self.popen_instances[len(self.popen_instances) - 1].pid}")

    def restore_usbmuxd_socket(self):
        print("--- Restoring /var/run/usbmuxd ---")
        
        # Kill tcpdump/socat instances
        for instance in self.popen_instances:
            cmd = f"sudo kill {instance.pid}"
            print(cmd)
            subprocess.check_call(cmd, shell=True)
        
        # Restore original socket
        cmd = "sudo mv /var/run/usbmuxd.orig /var/run/usbmuxd"
        print(cmd)
        subprocess.check_call(cmd, shell=True)

if __name__ == "__main__":
    Application().run()
