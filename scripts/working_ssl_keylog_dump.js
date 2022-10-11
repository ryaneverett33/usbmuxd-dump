// TODO, use this to fix the implementation in agent.js

function allocPointer(value) {
    const address = Memory.alloc(Process.pointerSize);
    Memory.writePointer(address, value);
    return address;
}

var ssl = Process.findModuleByName("/usr/lib/libssl.35.dylib");

// exports
var SSL_Connect_export = ssl.findExportByName("SSL_connect");
var SSL_get_session_export = ssl.findExportByName("SSL_get_session");
var i2d_ssl_session_export = ssl.findExportByName("i2d_SSL_SESSION");
var SSL_read_export = ssl.findExportByName("SSL_read");
var SSL_write_export = ssl.findExportByName("SSL_write");

// functions
var SSL_get_session = new NativeFunction(SSL_get_session_export, "pointer", ["pointer"]);
var i2d_SSL_SESSION = new NativeFunction(i2d_ssl_session_export, "int", ["pointer", "pointer"]);

function encodeSSLSession(session) {
    const length = i2d_SSL_SESSION(session, NULL);
    const address = Memory.alloc(length);

    i2d_SSL_SESSION(session, allocPointer(address));

    return Memory.readByteArray(address, length);
};

function handleSSL(ssl) {
    const session = SSL_get_session(ssl);
    send("session", encodeSSLSession(session));
} 

Interceptor.attach(SSL_Connect_export, {
    onEnter: function (args) {
        this.ssl = args[0];
    },
    onLeave: function (retvalue) {
        handleSSL(this.ssl);
    }
});
Interceptor.attach(SSL_read_export, {
    onEnter: function (args) {
        handleSSL(args[0]);
    }
});
Interceptor.attach(SSL_write_export, {
    onEnter: function (args) {
        handleSSL(args[0]);
    }
});