# usbmuxd-dump

Frida tool to dump [usbmuxd](https://www.theiphonewiki.com/wiki/Usbmux) traffic from Xcode. The tool dumps both standard TCP messages as well as SSL-encoded, but decrypted, messages to a Wireshark compatible `.pcap` file. 

## Usage

```sh
$ # Find the Xcode process to attach to 
$ frida-ps | grep Xcode
34772  Xcode                                                   
34773  com.apple.dt.Xcode.DeveloperSystemPolicyService
$ # Run dumpmuxd.py similar to how you would with Frida and attach to the Xcode instance
$ python dumpmuxd.py -p 34772 -o wireshark/captured.pcap -t logs/dump.log --tcpdump wireshark/socat.tcp.pcap
```

The above command will create three kinds of log files: a Wireshark-compatible packet capture (`captured.pcap`) with fully decrypted messaging, a `tcpdump`/`socat` packet capture (`socat.tcp.pcap`) with a mix of encrypted/non-encrypted traffic, and text files for each connection instance that Xcode creates (`logs/dump.log`). The `-t`/`--text` flag is a bit confusing because it will create multiple log files. For example, `-t logs/dump.log` may produce `logs/dump.log.66` and `logs/dump.log.10` using `logs/dump.log` as the base name of any resulting files.

The logs created by this tool have their own unique set of pros and cons for use in understanding how `usbmuxd` works. The `socat`/`tcpdump` output captured by the `--tcpdump` flag is great for making use of Wireshark and captures the data exactly. However, any SSL traffic is encrypted at this stage which makes it harder to use. The re-constructed packet-capture data from the `-o` flag attempt to make this easier by presenting the SSL traffic as decrypted, but the packet capture in this tool is rudimentary compared to a tool like `tcpdump`. Finally, logs created by the `-t` flag are great for quickly looking at captured data but struggle with some binary-plists and raw non-plist backed traffic.

### Example text dump

```
[00:00:01.0258] 0.0.0.0:0 -> 97.114.47.114:12146 [send]
[PLIST]
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>BundleID</key>
	<string>com.apple.dt.Xcode</string>
	<key>ClientVersionString</key>
	<string>usbmuxd-521</string>
...
</dict>
</plist>
[00:00:01.0298] 0.0.0.0:0 -> 97.114.47.114:12146 [recv]
[PLIST]
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MessageType</key>
	<string>Result</string>
	<key>Number</key>
	<integer>0</integer>
</dict>
</plist>
[00:00:01.0310] 0.0.0.0:0 -> 97.114.47.114:12146 [send]
[PLIST]
...
```

The `--dump-plists` flag can be used to make reading text dump files easier by dumping recognized `.plist`s to a file and printing only the first few lines to the text dump.

## Installation

This tool requires the `pyasn1` and `frida-tools` packages to work:
```sh
$ pip3 install -r requirements.txt
```

## Thanks

This project is based on efforts by these projects:
- [frida-sslkeylog](https://github.com/saleemrashid/frida-sslkeylog)
- [ssl_logger](https://github.com/google/ssl_logger)