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

@[extern "bio_handshake"]
opaque BIO.handshake : @& BIO -> IO Unit

@[extern "bio_ssl_shutdown"]
opaque BIO.ssl_shutdown : @& BIO -> BaseIO Unit

section

@[match_pattern, expose]
def ERR_RETRY (s : String) : IO.Error := IO.Error.resourceExhausted none 11 s

@[match_pattern, expose]
def ERR_RETRY_WRITE : IO.Error := ERR_RETRY "SHOULD_WRITE"

@[match_pattern, expose]
def ERR_RETRY_READ : IO.Error := ERR_RETRY "SHOULD_READ"

@[match_pattern, expose]
def ERR_RETRY_IO_SPECIAL : IO.Error := ERR_RETRY "SHOULD_IO_SPECIAL"

end

section

partial def BIO.writeAsync (bio : BIO) (data : ByteArray) : Async Unit := do
  try
    bio.write data
  catch
  | ERR_RETRY_WRITE => -- EAGAIN
    sleep 1
    BIO.writeAsync bio data
  | err => throw err

partial def BIO.readAsync? (bio : BIO) (max : USize) : Async (Option ByteArray) := do
  try
    some <$> bio.read max
  catch
  | ERR_RETRY_READ => -- EAGAIN
    sleep 1
    BIO.readAsync? bio max
  | err@(ERR_RETRY _) => throw err
  | _ => return none -- closed

partial def BIO.handshakeAsync (bio : BIO) : Async Unit := do
  try
    bio.handshake
  catch
  | ERR_RETRY _ => -- EAGAIN
    sleep 1
    BIO.handshakeAsync bio
  | err => throw err

end
