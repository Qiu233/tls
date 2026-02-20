module

public import Tls.Internal.FFI
public import Http.Client

open Tls.Internal.FFI
open Std.Internal.IO.Async
open Std.Internal.IO.Async.TCP
open Http
open System

public section

structure TLSClientConfig where
  serverName? : Option String := none
  caCertFile? : Option String := none
  alpnProtocols : Array String := #["h2", "http/1.1"]
  requireALPN? : Option String := some "h2"
  deriving Inhabited

def tls_transport (cfg : TLSClientConfig) : Transport where
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
    match cfg.caCertFile? with
    | some path => ctx.load_verify_file path
    | none => ctx.set_default_verify_paths
    ctx.set_alpn_protocols cfg.alpnProtocols
    let tls ← BIO.mkSSL ctx 1
    match cfg.serverName? with
    | some serverName => tls.set_sni serverName
    | none => pure ()
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
      match cfg.requireALPN? with
      | none => pure ()
      | some expected =>
          let selected? ← tls.negotiatedALPN?
          if selected? != some expected then
            throw <| IO.userError s!"TLS ALPN mismatch: expected {expected}, negotiated {selected?.getD "<none>"}"
      return conn
    catch e =>
      sock.shutdown
      throw e
