-- module

import Tls.Internal.FFI
import Http.Client
import Std

#check Std.Internal.IO.Async.TCP.Socket.Client.send
#check Std.Internal.IO.Async.TCP.Socket.Client
#check Std.Internal.UV.TCP.Socket
#check Std.Internal.UV.TCP.Socket

open Tls.Internal.FFI
open Std.Internal.IO.Async

#check IO.Error

namespace Tls.Internal.FFI

partial def BIO.writeAsync (bio : BIO) (data : ByteArray) : Async Unit := do
  try
    bio.write data
  catch err =>
    let rt ← bio.shouldRetry
    if !rt then
      throw err
    sleep 1
    BIO.writeAsync bio data

partial def BIO.readAsync (bio : BIO) (max : USize) : Async ByteArray := do
  try
    bio.read max
  catch err =>
    let rt ← bio.shouldRetry
    if !rt then
      throw err
    sleep 1
    BIO.readAsync bio max

partial def BIO.handshakeAsync (bio : BIO) : Async Unit := do
  try
    bio.handshake
  catch err =>
    let rt ← bio.shouldRetry
    if !rt then
      throw err
    sleep 1
    BIO.handshakeAsync bio

end Tls.Internal.FFI

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

def main : IO Unit := do
  let trans : Transport := {
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
          recv? := fun n => do
            let r ← tls.readAsync (USize.ofNat n.toNat)
            if r.isEmpty then return none
            return r
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
    }
  let client : Http.HttpClient := { host := "127.0.0.1", port := 8443, transport := trans }
  let resp ← client.getAsync "/" |>.wait
  println! "!{repr resp}"
