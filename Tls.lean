module

public import Tls.Internal.FFI
public import Http.Client

open Tls.Internal.FFI
open Std.Internal.IO.Async
open Std.Internal.IO.Async.TCP
open Http
open System

public section

def Http.Transport.tls
  (requireALPN? : Option String)
  (alpnProtocols : Array String)
  (serverName? : Option String := none)
  (caCertFile? : Option String := none)
  (verify_peer : Bool := true)
    : Transport where
  connect := fun addr => do
    let sock ← Socket.Client.mk
    let send (bs : ByteArray) : Async Unit := do
      sock.send bs
    let recv (size : USize) : Async ByteArray := do
      match (← sock.recv? (UInt64.ofNat size.toNat)) with
      | some d => return d
      | none   => return ByteArray.empty
    let stream : Stream := { send, recv, flush := pure () }
    let outBIO ← BIO.ofStream stream
    let meth ← SSLMethod.TLS
    let ctx ← SSLContext.new meth
    if verify_peer then
      ctx.set_verify SSL_VERIFY_PEER
    match caCertFile? with
    | some path => ctx.load_verify_file path
    | none => ctx.set_default_verify_paths
    ctx.set_alpn_protocols alpnProtocols
    let tls ← BIO.mkSSL ctx 1
    if let some serverName := serverName? then
      tls.set_sni serverName
    let tls ← tls.push outBIO
    let conn : Transport.Connection :=
      { send := fun bytes => do
          tls.writeAsync bytes
          tls.flush
        recv? := fun n => tls.readAsync? (USize.ofNat n.toNat)
        shutdown := do
          tls.ssl_shutdown
          sock.shutdown
        readBuffer := ← IO.mkRef {}
      }
    sock.connect addr
    try
      tls.handshakeAsync
      if let some expected := requireALPN? then
        let selected? ← tls.negotiatedALPN?
        if selected? != some expected then
          throw <| IO.userError s!"TLS ALPN mismatch: expected {expected}, negotiated {selected?.getD "<none>"}"
      return conn
    catch e =>
      sock.shutdown
      throw e

/--
## HTTPS client
* If `caCertFile?` is `none`, the default path/files are used.
* If `serverName?` is `none`, SNI is disabled.
* If `verify_peer` is `false`, verify is disabled.
-/
def Http.HttpClient.mkTLS
  (host : String)
  (port : UInt16 := 443)
  (protocol : Http.Connection.Protocol := .http2)
  (caCertFile? : Option String := none)
  (serverName? : Option String := some host)
  (verify_peer : Bool := true)
    : Http.HttpClient :=
  let (alpnProtocols, requireALPN?) :=
    match protocol with
    | .http1_1 => (#["http/1.1"], some "http/1.1")
    | .http2   => (#["h2", "http/1.1"], some "h2")
    | .unknown => (#["http/1.1"], none)
  let transport := Transport.tls requireALPN? alpnProtocols serverName? caCertFile? verify_peer
  { host, port, protocol, transport }
