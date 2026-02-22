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
  (protocol : IO.Ref Protocol)
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
      let selected? ← tls.negotiatedALPN?
      if let some selected := selected? then
        match selected with
        | "http/1.1" => protocol.set .http1_1
        | "h2" => protocol.set .http2
        | _ =>
          protocol.set (.unrecognized selected)
          throw <| IO.userError s!"TLS ALPN mismatch: negotiated {selected} is unrecognized"
      else
        protocol.set .unknown -- TODO: probe for protocol?
        throw <| IO.userError s!"TLS ALPN failed: no negotiated protocol"
      if let some expected := requireALPN? then
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
* Prefer specifying `protocol`.
-/
def Http.HttpClient.mkTLS
  (host : String)
  (port : UInt16 := 443)
  (protocol : Http.Protocol := .unknown)
  (caCertFile? : Option String := none)
  (serverName? : Option String := some host)
  (verify_peer : Bool := true)
    : BaseIO Http.HttpClient := do
  let (alpnProtocols, requireALPN?) :=
    match protocol with
    | .http1_1 => (#["http/1.1"], some "http/1.1")
    | .http2   => (#["h2", "http/1.1"], some "h2")
    | .unknown => (#["http/1.1"], none)
    | .unrecognized x => (#[x], some x)
  let protocol ← IO.mkRef protocol
  let transport := Transport.tls protocol requireALPN? alpnProtocols serverName? caCertFile? verify_peer
  return { host, port, protocol, transport }
