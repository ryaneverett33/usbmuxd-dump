    /* Useful C snippets
struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};
struct in_addr {
    unsigned long s_addr;  // load with inet_aton()
};
    */


var ssl = Process.findModuleByName("/usr/lib/libssl.35.dylib");
var libc = Process.findModuleByName("/usr/lib/libSystem.B.dylib");

// SSL exports
var SSL_connect_export = ssl.findExportByName("SSL_connect");
var SSL_get_session_export = ssl.findExportByName("SSL_get_session");
var i2d_ssl_session_export = ssl.findExportByName("i2d_SSL_SESSION");
var SSL_read_export = ssl.findExportByName("SSL_read");
var SSL_write_export = ssl.findExportByName("SSL_write");
var SSL_get_fd_export = ssl.findExportByName("SSL_get_fd");

// libc exports
var connect_export = libc.findExportByName("connect");
var send_export = libc.findExportByName("send");
var recv_export = libc.findExportByName("recv");
var getsockname_export = libc.findExportByName("getsockname");
var getpeername_export = libc.findExportByName("getpeername");
var ntohs_export = libc.findExportByName("ntohs");
var ntohl_export = libc.findExportByName("ntohl");
var inet_ntoa_export = libc.findExportByName("inet_ntoa");

// libc functions
var getsockname = new NativeFunction(getsockname_export, "int", ["int", "pointer", "pointer"]);
var getpeername = new NativeFunction(getpeername_export, "int", ["int", "pointer", "pointer"]);
var ntohs = new NativeFunction(ntohs_export, "uint16", ["uint16"]);
var ntohl = new NativeFunction(ntohl_export, "uint32", ["uint32"]);
var inet_ntoa = new NativeFunction(inet_ntoa_export, "pointer", ["uint64"]);

// ssl functions
var SSL_get_session = new NativeFunction(SSL_get_session_export, "pointer", ["pointer"]);
var i2d_SSL_SESSION = new NativeFunction(i2d_ssl_session_export, "int", ["pointer", "pointer"]);
var SSL_get_fd = new NativeFunction(SSL_get_fd_export, "int", ["pointer"]);

function encodeSSLSession(session) {
    // TODO get this to work
    // int i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp);

    // calculate the length first before performing the transformation
    var length = i2d_SSL_SESSION(session, NULL);

    // Allocate storage to store the string
    var address = Memory.alloc(length);
    var ptrPtr = Memory.alloc(Process.pointerSize);
    ptrPtr.writePointer(address);

    // actually make the ASN1 representation
    // var address = Memory.alloc(Process.pointerSize);
    // Memory.writePointer(address, length);
    i2d_SSL_SESSION(session, ptrPtr);

    return Memory.readByteArray(address, length);
};

function __getXInfo(sockfd, delegating_function) {
    var addrLen = Memory.alloc(4);
    var addrStruct = Memory.alloc(16);      // type: struct sockaddr_in
    Memory.writeU32(addrLen, 16);

    delegating_function(sockfd, addrStruct, addrLen);

    var port = ntohs(Memory.readU16(addrStruct.add(2)));    // sin_port
    var address = ntohl(Memory.readU32(addrStruct.add(4)));       // sin_addr
    // Comment this back in for runtime debugging
    // var address = Memory.readCString(inet_ntoa(Memory.readU32(addrStruct.add(4))));
    return [address, port];
}

function getSourceInfo(sockfd) {
    return __getXInfo(sockfd, getsockname);
}
function getDestinationInfo(sockfd) {
    return __getXInfo(sockfd, getpeername);
}

/*Interceptor.attach(SSL_connect_export, {
    onEnter: function (args) {
        this.sslobj = args[0];
    },
    onLeave: function (retvalue) {
        // int SSL_connect(SSL *ssl);
        const session = SSL_get_session(this.sslobj);

        send({
            type: "connect",
            ssl_session: encodeSSLSession(session)
        })
    }
});*/

Interceptor.attach(SSL_read_export, {
    onEnter: function (args) {
        this.sslobj = args[0];
        this.buff = args[1];
    },
    onLeave: function(retval) {
        // int SSL_read(SSL *ssl, void *buf, int num);
        var fd = SSL_get_fd(this.sslobj)
        var length = parseInt(retval);
        var [srcAddr, srcPort] = getSourceInfo(fd);
        var [destAddr, destPort] = getDestinationInfo(fd);
        //const session = SSL_get_session(args[0]);

        // console.log(`Received SSL ${length} bytes from ${srcAddr}:${srcPort}`);
        // console.log(Memory.readCString(this.buff, length));

        var message = new Uint8Array(Memory.readByteArray(this.buff, length));
        send({
            type: "recv",
            message: Array.from(message),
            timestamp: Date.now(),
            length: length,
            fd: fd,
            src: {
                address: srcAddr,
                port: srcPort
            },
            dest: {
                address: destAddr,
                port: destAddr
            }
            //ssl_session: encodeSSLSession(session)
        });
    }
});
Interceptor.attach(SSL_write_export, {
    onEnter: function (args) {
        // int SSL_write(SSL *ssl, const void *buf, int num);
        var fd = SSL_get_fd(args[0]);
        var length = parseInt(args[2]);
        var [destAddr, destPort] = getDestinationInfo(fd);
        var [srcAddr, srcPort] = getDestinationInfo(fd);
        //const session = SSL_get_session(args[0]);

        // console.log(`Sending SSL ${length} bytes to ${destAddr}:${destPort}`);
        // console.log(Memory.readCString(args[1], length));
        var message = new Uint8Array(Memory.readByteArray(args[1], length));
                send({
            type: "send",
            message: Array.from(message),
            timestamp: Date.now(),
            length: length,
            fd: fd,
            src: {
                address: srcAddr,
                port: srcPort
            },
            dest: {
                address: destAddr,
                port: destAddr
            }
            //ssl_session: encodeSSLSession(session)
        });
    }
});
Interceptor.attach(send_export, {
    onEnter: function (args) {
        // int send(int sockfd, const void *msg, int len, int flags);
        var fd = parseInt(args[0]);
        var length = parseInt(args[2]);
        var [srcAddr, srcPort] = getSourceInfo(fd);
        var [destAddr, destPort] = getDestinationInfo(fd);

        //console.log(`Sending ${length} bytes from ${srcAddr}:${srcPort} to ${destAddr}:${destPort}`);
        //console.log(Memory.readCString(args[1], length));
        
        var message = new Uint8Array(Memory.readByteArray(args[1], length));
        send({
            type: "send",
            message: Array.from(message),
            timestamp: Date.now(),
            length: length,
            fd: fd,
            src: {
                address: srcAddr,
                port: srcPort
            },
            dest: {
                address: destAddr,
                port: destAddr
            }
            //ssl_session: encodeSSLSession(session)
        });
    }
});
Interceptor.attach(recv_export, {
    // ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    onEnter: function(args) {
        this.sockfd = parseInt(args[0]);
        this.buff = args[1];
    },
    onLeave: function(retval) {
        var length = parseInt(retval);
        var [srcAddr, srcPort] = getSourceInfo(this.sockfd);
        var [destAddr, destPort] = getDestinationInfo(this.sockfd);

        //console.log(`Received ${length} bytes from ${srcAddr}:${srcPort} to ${dstAddr}:${dstPort}`);
        //console.log(Memory.readCString(this.buff, length));
        
        
        var message = new Uint8Array(Memory.readByteArray(this.buff, length));
        send({
            type: "recv",
            message: Array.from(message),
            timestamp: Date.now(),
            length: length,
            fd: this.sockfd,
            src: {
                address: srcAddr,
                port: srcPort
            },
            dest: {
                address: destAddr,
                port: destAddr
            }
            //ssl_session: encodeSSLSession(session)
        });
    }
});