module

meta import Tls.Meta.FFIType
public import Std

@[extern "initialize_native"]
private opaque initialize_native : IO Unit

initialize initialize_native

namespace Tls.Internal.FFI

public declare_ffi_type% SSLMethod : Type
public declare_ffi_type% SSLContext : Type
public declare_ffi_type% BIO : Type

@[extern "ssl_tls_method"]
public opaque SSLMethod.TLS : BaseIO SSLMethod

@[extern "ssl_ssl_ctx_new"]
public opaque SSLContext.new : @& SSLMethod → IO SSLContext

open Std.Internal.IO.Async in
public structure Stream : Type where
  recv : USize → Async ByteArray
  send : ByteArray → Async Unit
  flush : Async Unit

@[extern "bio_of_stream"]
public opaque BIO.ofStream : Stream -> IO BIO

@[extern "ssl_errors"]
public opaque errors : BaseIO (Array String)

-- there is a lifetime issue with a pair
-- it remains to see whether one half (asymmetrically) should keep the other alive
@[extern "bio_new_pair"]
private opaque BIO.mkPair : IO (BIO × BIO)

@[extern "bio_mem"]
public opaque BIO.mkMem : IO BIO

@[extern "bio_buffer"]
public opaque BIO.mkBuffer : IO BIO

@[extern "bio_base64"]
public opaque BIO.mkBase64 : IO BIO

@[extern "bio_push"]
public opaque BIO.push : BIO -> BIO -> BaseIO BIO

@[extern "bio_ssl"]
public opaque BIO.mkSSL : @& SSLContext -> Int32 -> IO BIO

@[extern "bio_read"]
public opaque BIO.read : @& BIO -> USize -> IO ByteArray

@[extern "bio_write"]
public opaque BIO.write : @& BIO -> ByteArray -> IO Unit

@[extern "bio_flush"]
public opaque BIO.flush : @& BIO -> IO Unit

@[extern "bio_should_retry"]
public opaque BIO.shouldRetry : @& BIO -> BaseIO Bool

@[extern "bio_should_write"]
public opaque BIO.shouldWrite : @& BIO -> BaseIO Bool

@[extern "bio_should_read"]
public opaque BIO.shouldRead : @& BIO -> BaseIO Bool

@[extern "error_to_io_user_error"]
public opaque BIO.getAllError : BaseIO IO.Error

@[extern "ssl_ctx_load_verify_file"]
public opaque SSLContext.load_verify_file : @& SSLContext -> String -> IO Unit

@[extern "bio_handshake"]
public opaque BIO.handshake : @& BIO -> IO Unit

@[extern "bio_ssl_shutdown"]
public opaque BIO.ssl_shutdown : @& BIO -> BaseIO Unit
