module

meta import Tls.Meta.FFIType
public import Std

@[extern "initialize_native"]
private opaque initialize_native : IO Unit

initialize initialize_native

public section

namespace Tls.FFI

-- @[extern "lean_f"]
-- public opaque f : Unit → Int32

public declare_ffi_type% SSLMethod : Type
public declare_ffi_type% SSLContext : Type
public declare_ffi_type% BIO : Type

@[extern "ssl_tls_method"]
public opaque SSLMethod.TLS : IO SSLMethod

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

@[extern "bio_new_pair"]
public opaque BIO.mkPair : IO (BIO × BIO)

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





#exit


#check BaseIO
#check  BaseIO (Std.Internal.IO.Async.MaybeTask Nat)

def M : Type → Type := fun T => BaseIO (Std.Internal.IO.Async.MaybeTask (Except IO.Error T))

#check Task
#check BaseIO.asTask
#check IO.Promise
#check Std.Internal.IO.Async.Async.race
#check Task.bind
#check Std.Internal.IO.Async.Async
#check BaseIO.bindTask

@[extern "test"]
public opaque test : BaseIO ByteArray → ByteArray
#check Except
#check Task
#check IO.getTaskState
#check IO
