-- module

import Tls.Internal.FFI
import Http.Client
import Std

open Tls.Internal.FFI
open Std.Internal.IO.Async
open Std.Internal.IO.Async.TCP

open Http

deriving instance Repr for Std.Net.IPv4Addr
deriving instance Repr for Std.Net.IPv6Addr
deriving instance Repr for Uri.Host
deriving instance Repr for Uri.Authority
deriving instance Repr for Uri
deriving instance Repr for RequestTarget

instance : Repr (ByteArray) where
  reprPrec x _ := s!"{repr x.data}"

deriving instance Repr for Response

def tls_transport : Transport where
  connect := fun addr => do
    let sock ← Socket.Client.mk
    let send (bs : ByteArray) : Async Unit := do
      sock.send bs
    let recv (size : USize) : Async ByteArray := do
      match (← sock.recv? (UInt64.ofNat size.toNat)) with
      | some d => return d
      | none   => return ByteArray.empty   -- EOF
    let stream : Stream := { send, recv, flush := pure () }
    let outBIO ← BIO.ofStream stream
    let meth ← SSLMethod.TLS
    let ctx ← SSLContext.new meth
    ctx.load_verify_file "/home/qiu/dummyweb/.nginx/ssl/self.crt"
    let tls ← BIO.mkSSL ctx 1
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
      return conn
    catch e =>
      sock.shutdown
      throw e

def main : IO Unit := do
  let client : Http.HttpClient := { host := "127.0.0.1", port := 8443, transport := tls_transport }
  let resp ← client.getAsync "/" |>.wait
  println! "!{repr resp}"
