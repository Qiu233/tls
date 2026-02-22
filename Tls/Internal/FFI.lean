module

meta import Tls.Meta.FFIType
public import Std

public section

@[extern "initialize_native"]
private opaque initialize_native : IO Unit

initialize initialize_native

namespace Tls.Internal.FFI

declare_ffi_type% SSLMethod : Type
declare_ffi_type% SSLContext : Type
declare_ffi_type% BIO : Type

@[extern "ssl_tls_method"]
opaque SSLMethod.TLS : BaseIO SSLMethod

@[extern "ssl_ssl_ctx_new"]
opaque SSLContext.new : @& SSLMethod → IO SSLContext

open Std.Internal.IO.Async

structure Stream : Type where
  recv : USize → Async ByteArray
  send : ByteArray → Async Unit
  flush : Async Unit

@[extern "bio_of_stream"]
opaque BIO.ofStream : Stream -> IO BIO

@[extern "ssl_errors"]
opaque errors : BaseIO (Array String)

-- there is a lifetime issue with a pair
-- it remains to see whether one half (asymmetrically) should keep the other alive
@[extern "bio_new_pair"]
private opaque BIO.mkPair : IO (BIO × BIO)

@[extern "bio_mem"]
opaque BIO.mkMem : IO BIO

@[extern "bio_buffer"]
opaque BIO.mkBuffer : IO BIO

@[extern "bio_base64"]
opaque BIO.mkBase64 : IO BIO

@[extern "bio_push"]
opaque BIO.push : BIO -> BIO -> BaseIO BIO

@[extern "bio_ssl"]
opaque BIO.mkSSL : @& SSLContext -> Int32 -> IO BIO

@[extern "bio_read"]
opaque BIO.read : @& BIO -> USize -> IO ByteArray

@[extern "bio_write"]
opaque BIO.write : @& BIO -> ByteArray -> IO Unit

@[extern "bio_flush"]
opaque BIO.flush : @& BIO -> IO Unit

@[extern "bio_should_retry"]
opaque BIO.shouldRetry : @& BIO -> BaseIO Bool

@[extern "bio_should_write"]
opaque BIO.shouldWrite : @& BIO -> BaseIO Bool

@[extern "bio_should_read"]
opaque BIO.shouldRead : @& BIO -> BaseIO Bool

@[extern "bio_should_io_special"]
opaque BIO.shouldIOSpecial : @& BIO -> BaseIO Bool

@[extern "error_to_io_user_error"]
opaque BIO.getAllError : BaseIO IO.Error

@[extern "ssl_ctx_load_verify_file"]
opaque SSLContext.load_verify_file : @& SSLContext -> String -> IO Unit

@[extern "ssl_ctx_set_default_verify_paths"]
opaque SSLContext.set_default_verify_paths : @& SSLContext -> IO Unit

@[extern "ssl_ctx_set_alpn_wire"]
opaque SSLContext.set_alpn_wire : @& SSLContext -> @& ByteArray -> IO Unit

@[extern "bio_handshake"]
opaque BIO.handshake : @& BIO -> IO Unit

@[extern "bio_ssl_shutdown"]
opaque BIO.ssl_shutdown : @& BIO -> BaseIO Unit

@[extern "bio_set_sni"]
opaque BIO.set_sni : @& BIO -> String -> IO Unit

@[extern "bio_get_alpn_selected"]
opaque BIO.get_alpn_selected : @& BIO -> BaseIO (Option ByteArray)

def SSL_VERIFY_NONE                 : Int32 := 0x00
def SSL_VERIFY_PEER                 : Int32 := 0x01
def SSL_VERIFY_FAIL_IF_NO_PEER_CERT : Int32 := 0x02
def SSL_VERIFY_CLIENT_ONCE          : Int32 := 0x04
def SSL_VERIFY_POST_HANDSHAKE       : Int32 := 0x08

@[extern "ssl_ctx_set_verify"]
opaque SSLContext.set_verify : @& SSLContext -> Int32 -> BaseIO Unit

section

@[match_pattern, expose]
def ERR_RETRY (s : String) : IO.Error := IO.Error.resourceExhausted none 11 s -- 11 is EAGAIN

@[match_pattern, expose]
def ERR_RETRY_WRITE : IO.Error := ERR_RETRY "SHOULD_WRITE"

@[match_pattern, expose]
def ERR_RETRY_READ : IO.Error := ERR_RETRY "SHOULD_READ"

@[match_pattern, expose]
def ERR_RETRY_IO_SPECIAL : IO.Error := ERR_RETRY "SHOULD_IO_SPECIAL"

end

section

def encodeALPNWire (protocols : Array String) : IO ByteArray := do
  protocols.foldlM (init := ByteArray.empty) fun acc proto => do
    let bs := proto.toUTF8
    if bs.size > 255 then
      throw <| IO.userError s!"ALPN protocol is too long ({bs.size} bytes): {proto}"
    else
      let len : UInt8 := UInt8.ofNat bs.size
      return acc.push len ++ bs

def SSLContext.set_alpn_protocols (ctx : SSLContext) (protocols : Array String) : IO Unit := do
  let wire ← encodeALPNWire protocols
  ctx.set_alpn_wire wire

def BIO.negotiatedALPN? (bio : BIO) : BaseIO (Option String) := do
  match (← bio.get_alpn_selected) with
  | none => return none
  | some bs => return String.fromUTF8? bs

end

section

partial def BIO.writeAsync (bio : BIO) (data : ByteArray) : Async Unit := do
  try
    bio.write data
  catch
  | ERR_RETRY_WRITE =>
    sleep 1
    BIO.writeAsync bio data
  | err => throw err

partial def BIO.readAsync? (bio : BIO) (max : USize) : Async (Option ByteArray) := do
  try
    some <$> bio.read max
  catch
  | ERR_RETRY_READ =>
    sleep 1
    BIO.readAsync? bio max
  | err@(ERR_RETRY _) => throw err
  | _ => return none

partial def BIO.handshakeAsync (bio : BIO) : Async Unit := do
  try
    bio.handshake
  catch
  | ERR_RETRY _ =>
    sleep 1
    BIO.handshakeAsync bio
  | err => throw err

end
