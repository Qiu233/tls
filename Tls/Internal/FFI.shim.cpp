#include <openssl/ssl.h>
#include <openssl/err.h>
#include <lean/lean.h>
#include <string>
#include <vector>
#include <functional>
#include <optional>
#include "FFI.shim.h"

SIMPLE_EXTERNAL_CLASS(ssl_method, const SSL_METHOD *);
SIMPLE_EXTERNAL_CLASS(ssl_ctx, SSL_CTX *);
SIMPLE_EXTERNAL_CLASS(bio, BIO *);

// IO Unit
extern "C" lean_object *initialize_native()
{
  EXTERNAL_CLASS_NAME(ssl_method) = lean_register_external_class([](void *ptr)
                                                                 {
                                                                   // we don't need to free it.
                                                                 },
                                                                 [](void *obj, lean_object *fn) {});
  EXTERNAL_CLASS_NAME(ssl_ctx) = lean_register_external_class([](void *ptr)
                                                              {
        auto ctx = static_cast<SSL_CTX*>(ptr);
        SSL_CTX_free(ctx); }, [](void *obj, lean_object *fn) {});
  EXTERNAL_CLASS_NAME(bio) = lean_register_external_class([](void *ptr)
                                                          {
        auto bio = static_cast<BIO *>(ptr);
        BIO_free_all(bio); }, [](void *obj, lean_object *fn) {});
  return lean_io_result_mk_ok(lean_box(0));
}

// BaseIO SSLMethod
extern "C" lean_object *ssl_tls_method()
{
  const SSL_METHOD *method = TLS_method();
  return lean_alloc_external(EXTERNAL_CLASS_NAME(ssl_method), (void *)method);
}

static std::string get_all_error()
{
  std::string err_res = "";
  const size_t BUFSIZE = 1024;
  auto buf = std::make_unique<char[]>(BUFSIZE);
  unsigned long e = 0;
  bool first = true;
  while ((e = ERR_get_error()) != 0)
  {
    ERR_error_string_n(e, buf.get(), BUFSIZE);
    if (!first)
    {
      err_res += "\n";
      first = false;
    }
    err_res += buf.get();
  }
  return err_res;
}

// BaseIO IO.Error
extern "C" lean_obj_res error_to_io_user_error()
{
  std::string err_res = get_all_error();
  auto str = lean_mk_string_from_bytes(err_res.c_str(), err_res.size());
  return lean_mk_io_user_error(str);
}

#define SSL_FALLIBLE_NULL_ON_ERROR(WORK, FAIL) ({ \
  ERR_clear_error(); \
  auto __var__ = WORK; \
  if (!__var__) { \
    FAIL; \
  } \
  __var__; \
  })

#define SSL_FALLIBLE_NULL_ON_ERROR_IO(WORK) \
  SSL_FALLIBLE_NULL_ON_ERROR(WORK, return lean_io_result_mk_error(error_to_io_user_error()))

#define SSL_FALLIBLE_NULL_ON_ERROR_IO_EC(WORK) \
  auto res = SSL_FALLIBLE_NULL_ON_ERROR_IO(WORK); \
  return lean_io_result_mk_ok(wrapEC(res)); \
  static_assert(true, "") // force semicolon


// @& SSLMethod -> SSLContext
extern "C" lean_object *ssl_ssl_ctx_new(lean_object *method)
{
  const SSL_METHOD *meth = static_cast<const SSL_METHOD *>(lean_get_external_data(method));
  SSL_FALLIBLE_NULL_ON_ERROR_IO_EC(SSL_CTX_new(meth));
}

class LeanStreamCtx
{
public:
  LeanObjRef stream;
  LeanObjRef pending_read_task;
  LeanObjRef pending_send_task;
  size_t pending_send_len;
  LeanObjRef pending_flush_task;
  LeanStreamCtx(LeanObjRef s) : stream(s) {}
};

typedef struct StreamOps
{
  enum class Status : int {
    FATAL = -1,
    AGAIN = 0,
    SUCCESS = 1
  };
  // Return values convention (you choose; this example uses):
  //   1 = success, 0 = would-block/try again, -1 = fatal error (set *err)
  std::unique_ptr<LeanStreamCtx> ctx;
  std::function<Status(LeanStreamCtx *ctx, unsigned char *buf, size_t len, size_t *out_n, LeanObjRef & err)> read;
  std::function<Status(LeanStreamCtx *ctx, const unsigned char *buf, size_t len, size_t *out_n, LeanObjRef & err)> write;
  std::function<Status(LeanStreamCtx *ctx, LeanObjRef & err)> flush;
  // StreamOps() = delete;
  // TODO: remove default constructor
} StreamOps;

typedef struct StreamBioState
{
  StreamOps ops;
  LeanObjRef last_err; // for debugging
  StreamBioState() = delete;
  StreamBioState(StreamOps && o) : ops(std::move(o)) {}
} StreamBioState;

static int streambio_create(BIO *b)
{
  BIO_set_data(b, nullptr); // we'll set data after BIO_new()
  return 1;
}

static int streambio_destroy(BIO *b)
{
  if (b == nullptr)
    return 0;
  StreamBioState *st = (StreamBioState *)BIO_get_data(b);
  delete st;
  BIO_set_data(b, nullptr);
  return 1;
}

// BIO_meth_set_read_ex callback signature uses BIO_read_ex semantics
static int streambio_read_ex(BIO *b, char *out, size_t outl, size_t *readbytes)
{
  if (readbytes)
    *readbytes = 0;
  StreamBioState *st = (StreamBioState *)BIO_get_data(b); // store/retrieve custom data
  if (!st || !st->ops.read || !out)
    return 0;

  BIO_clear_retry_flags(b);

  size_t n = 0;
  StreamOps::Status rc = st->ops.read(st->ops.ctx.get(), (unsigned char *)out, outl, &n, st->last_err);

  switch(rc) {
  case StreamOps::Status::SUCCESS:
    if (readbytes)
      *readbytes = n;
    return 1; // success
  case StreamOps::Status::AGAIN:
    // would-block / try again later
    BIO_set_retry_read(b);
    return 0;
  case StreamOps::Status::FATAL:
  default:
    return 0;
  }
}

// BIO_meth_set_write_ex callback signature uses BIO_write_ex semantics
static int streambio_write_ex(BIO *b, const char *in, size_t inl, size_t *written)
{
  if (written)
    *written = 0;
  StreamBioState *st = (StreamBioState *)BIO_get_data(b);
  if (!st || !st->ops.write || (!in && inl != 0))
    return 0;

  BIO_clear_retry_flags(b);

  size_t n = 0;
  StreamOps::Status rc = st->ops.write(st->ops.ctx.get(), (const unsigned char *)in, inl, &n, st->last_err);

  switch(rc) {
  case StreamOps::Status::SUCCESS:
    if (written)
      *written = n;
    return 1;
  case StreamOps::Status::AGAIN:
    BIO_set_retry_write(b);
    return 0;
  case StreamOps::Status::FATAL:
  default:
    return 0;
  }
}

static long streambio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
  (void)num;
  (void)ptr;
  StreamBioState *st = (StreamBioState *)BIO_get_data(b);

  switch (cmd)
  {
  case BIO_CTRL_FLUSH:
    // SSL_set_bio requires custom wbio to support BIO_flush via BIO_CTRL_FLUSH
    if (st && st->ops.flush)
    {
      BIO_clear_retry_flags(b);
      StreamOps::Status rc = st->ops.flush(st->ops.ctx.get(), st->last_err);
      return (rc == StreamOps::Status::SUCCESS) ? 1 : 0;
    }
    return 1; // "no-op flush" is acceptable if flushing unnecessary

  default:
    return 0;
  }
}

const char * LEAN_STREAM_BIO_NAME = "lean-stream-bio";

static BIO_METHOD *streambio_method()
{
  static BIO_METHOD *m = nullptr;
  if (m != nullptr)
    return m;

  // type: source/sink is appropriate for a transport BIO
  m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, LEAN_STREAM_BIO_NAME);
  assert(m != nullptr);
  if (!m)
    return nullptr;

  BIO_meth_set_create(m, streambio_create);
  BIO_meth_set_destroy(m, streambio_destroy);
  BIO_meth_set_read_ex(m, streambio_read_ex);
  BIO_meth_set_write_ex(m, streambio_write_ex);
  BIO_meth_set_ctrl(m, streambio_ctrl);
  return m;
}

static BIO *BIO_new_stream(StreamBioState *state)
{
  BIO_METHOD *m = streambio_method();
  if (!m)
    return nullptr;
  BIO *b = BIO_new(m);
  if (!b)
    return nullptr;
  BIO_set_data(b, state); // attach your per-stream state
  BIO_set_init(b, 1);
  return b;
}

// BaseIO a -> a
static LeanObjRef unwrap_base_io(LeanObjRef x)
{
  lean_inc(x);
  lean_obj_res y = lean_apply_1(x, lean_io_mk_world());
  return LeanObjRef(y);
}

static LeanObjRef mk_byte_array_from_buf(const unsigned char *buf, size_t len)
{
  lean_obj_res ba = lean_alloc_sarray(/*elem_size*/ 1, /*size*/ len, /*cap*/ len);
  memcpy(lean_sarray_cptr(ba), buf, len);
  return LeanObjRef(ba);
}

static StreamOps::Status poll_task(LeanObjRef & task, LeanObjRef & res, LeanObjRef & err)
{
  uint8_t st = lean_io_get_task_state_core(task); // 0 waiting, 1 running, 2 finished
  if (st == 0 || st == 1)
    return StreamOps::Status::AGAIN; // would-block

  // finished
  LeanObjRef except = task.task_get(); // blocks only if not finished
  task.steal_drop();

  // Except.error
  if (lean_obj_tag(except) == 0)
  {
    err = except.ctor_get(0);
    return StreamOps::Status::FATAL;
  }
  // Except.ok
  res = except.ctor_get(0);
  return StreamOps::Status::SUCCESS;
}

static StreamOps::Status poll_unit_task(LeanObjRef & task, LeanObjRef & err)
{
  LeanObjRef tmp;
  return poll_task(task, tmp, err);
}

// lean_obj_res lean_io_error_to_string(lean_obj_arg err);

static StreamOps::Status lean_read(LeanStreamCtx *ctx, unsigned char *buf, size_t len, size_t *out_n, LeanObjRef & err)
{
  if (!ctx->pending_read_task.is_unit())
  {
    LeanObjRef data;
    StreamOps::Status r = poll_task(ctx->pending_read_task, data, err);
    if (r == StreamOps::Status::SUCCESS)
    {
      size_t n = lean_sarray_size(data);
      if (n > len)
        n = len; // TODO: throw error? The stream implementation cannot return more than requested.
      memcpy(buf, lean_sarray_cptr(data), n);
      *out_n = n;
    }
    return r;
  }
  LeanObjRef recv = ctx->stream.ctor_get(0);              // USize → Async ByteArray
  lean_inc(recv);
  LeanObjRef bs_async(lean_apply_1(recv, lean_box_usize(len))); // Async ByteArray
  LeanObjRef maybe = unwrap_base_io(bs_async);            // Std.Internal.IO.Async.MaybeTask (Except IO.Error ByteArray)

  if (lean_obj_tag(maybe) == 0)
  { // MaybeTask.pure
    LeanObjRef except = maybe.ctor_get(0); // Except ...

    // same Except handling as above
    if (lean_obj_tag(except) == 0)
    {
      err = except.ctor_get(0);
      return StreamOps::Status::FATAL;
    }
    else
    {
      LeanObjRef bs = except.ctor_get(0);
      size_t n = lean_sarray_size(bs);
      if (n > len)
        n = len;
      memcpy(buf, lean_sarray_cptr(bs), n);
      *out_n = n;
      return StreamOps::Status::SUCCESS;
    }
  }
  else
  { // MaybeTask.ofTask
    LeanObjRef task = maybe.ctor_get(0); // Task (Except ...)
    ctx->pending_read_task.swap(task); // stash it
    return StreamOps::Status::AGAIN;
  }
}

static StreamOps::Status lean_write(LeanStreamCtx *ctx, const unsigned char *buf, size_t len,
                      size_t *out_n, LeanObjRef & err)
{
  *out_n = 0;

  // If we already have a pending send task, just poll it.
  if (!ctx->pending_send_task.is_unit())
  {
    StreamOps::Status r = poll_unit_task(ctx->pending_send_task, err);
    if (r == StreamOps::Status::SUCCESS)
    {
      *out_n = ctx->pending_send_len; // the bytes that are now confirmed sent
      ctx->pending_send_len = 0;
    }
    return r; // 1 success, 0 wouldblock, -1 fatal
  }

  LeanObjRef ba = mk_byte_array_from_buf(buf, len); // ByteArray
  LeanObjRef send = ctx->stream.ctor_get(1);  // ByteArray -> Async Unit
  lean_inc(send);
  lean_inc(ba);
  LeanObjRef unit_async(lean_apply_1(send, ba)); // Async Unit
  LeanObjRef maybe_task = unwrap_base_io(unit_async); // MaybeTask (Except IO.Error Unit)

  auto tag = lean_obj_tag(maybe_task);
  LeanObjRef inner = maybe_task.ctor_get(0);
  if (tag == 0) {
    if (lean_obj_tag(inner) == 0)
    { // error
      err = inner.ctor_get(0);
      *out_n = 0;
      return StreamOps::Status::FATAL;
    }
    else
    { // ok
      *out_n = len;
      return StreamOps::Status::SUCCESS;
    }
  } else {
    // stash it and report would-block
    ctx->pending_send_task.swap(inner);
    ctx->pending_send_len = len;

    *out_n = 0;
    return StreamOps::Status::AGAIN;
  }
}

static StreamOps::Status lean_flush(LeanStreamCtx *ctx, LeanObjRef & err)
{
  // Poll pending flush first
  if (!ctx->pending_flush_task.is_unit())
  {
    return poll_unit_task(ctx->pending_flush_task, err);
  }

  LeanObjRef flush_async = ctx->stream.ctor_get(2); // Async Unit
  LeanObjRef maybe_task = unwrap_base_io(flush_async); // MaybeTask (Except IO.Error Unit)

  auto tag = lean_obj_tag(maybe_task);
  LeanObjRef inner = maybe_task.ctor_get(0);
  if (tag == 0) {
    if (lean_obj_tag(inner) == 0)
    {
      err = inner.ctor_get(0);
      return StreamOps::Status::FATAL;
    }
    else
    {
      return StreamOps::Status::SUCCESS;
    }
  } else {
    ctx->pending_flush_task.swap(inner);
    return StreamOps::Status::AGAIN;
  }
}

// Stream -> IO BIO
extern "C" lean_obj_res bio_of_stream(lean_obj_arg stream)
{
  std::unique_ptr<LeanStreamCtx> ctx = std::make_unique<LeanStreamCtx>(std::move(LeanStreamCtx(LeanObjRef(stream))));
  StreamBioState *st = new StreamBioState(std::move(StreamOps{std::move(ctx), lean_read, lean_write, lean_flush}));
  SSL_FALLIBLE_NULL_ON_ERROR_IO_EC(BIO_new_stream(st));
}

// BaseIO (Array String)
extern "C" lean_obj_res ssl_errors()
{
  std::vector<std::string> err_res = std::vector<std::string>();
  const size_t BUFSIZE = 1024;
  auto buf = std::make_unique<char[]>(BUFSIZE);
  unsigned long e = 0;
  while ((e = ERR_get_error()) != 0)
  {
    ERR_error_string_n(e, buf.get(), BUFSIZE);
    err_res.push_back(buf.get());
  }
  auto arr = lean_alloc_array(err_res.size(), err_res.size());
  for (size_t i = 0; i < err_res.size(); i++)
  {
    auto s = err_res[i];
    auto str = lean_mk_string_from_bytes(s.c_str(), s.size());
    lean_array_set_core(arr, i, str);
  }
  return arr;
}

// IO (BIO × BIO)
extern "C" lean_obj_res bio_new_pair()
{
  BIO *b1, *b2;
  ERR_clear_error();
  if (!BIO_new_bio_pair(&b1, 0, &b2, 0))
    return lean_io_result_mk_error(error_to_io_user_error());
  auto b1_ = wrapEC<BIO *>(b1);
  auto b2_ = wrapEC<BIO *>(b2);
  auto pair = lean_alloc_ctor(0, 2, 0); // Prod.mk
  lean_ctor_set(pair, 0, b1_);
  lean_ctor_set(pair, 1, b2_);
  return lean_io_result_mk_ok(pair);
}

// BIO -> BIO -> BaseIO BIO
extern "C" lean_obj_res bio_push(lean_obj_arg a, lean_obj_arg b)
{
  BIO * a_ = unwrapEC<BIO *>(a);
  BIO * b_ = unwrapEC<BIO *>(b);
  BIO * r = BIO_push(a_, b_);
  BIO_up_ref(b_);
  lean_dec(b); // If the caller does not hold it anymore, then the external object is finalized, and BIO refcount will be decremented at once.
  return a;
}

// @& SSLContext -> Int32 -> IO BIO
extern "C" lean_obj_res bio_ssl(b_lean_obj_arg ctx, int client)
{
  auto ctx_ = unwrapEC<SSL_CTX *>(ctx);
  SSL_FALLIBLE_NULL_ON_ERROR_IO_EC(BIO_new_ssl(ctx_, client));
}

// Contract: BIOs must set exactly one retry flag among read/write/io_special.
lean_obj_res handle_retry_error(BIO * bio) {
  if (!BIO_should_retry(bio)) {
    std::string err_res = get_all_error();
    lean_obj_res err = lean_mk_string_from_bytes(err_res.c_str(), err_res.size());
    return lean_io_result_mk_error(lean_mk_io_user_error(err));
  }
  if (BIO_should_read(bio)) {
    return lean_io_result_mk_error(lean_mk_io_error_resource_exhausted(EAGAIN, lean_mk_string("READ")));
  }
  if (BIO_should_write(bio)) {
    return lean_io_result_mk_error(lean_mk_io_error_resource_exhausted(EAGAIN, lean_mk_string("WRITE")));
  }
  if (BIO_should_io_special(bio)) {
    return lean_io_result_mk_error(lean_mk_io_error_resource_exhausted(EAGAIN, lean_mk_string("IO_SPECIAL")));
  }
  lean_panic("handle_retry_error: BIO_should_retry returns true with no retry flag set.", true);
  return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string("handle_retry_error: BIO_should_retry returns true with no retry flag set.")));
}

// @& BIO -> USize -> IO ByteArray
extern "C" lean_obj_res bio_read(b_lean_obj_arg bio, size_t len)
{
  auto bio_ = unwrapEC<BIO *>(bio);
  auto arr = lean_alloc_sarray(1, 0, len); // ByteArray
  size_t read_bytes = 0;
  ERR_clear_error();
  if (!BIO_read_ex(bio_, lean_sarray_cptr(arr), len, &read_bytes))
  {
    lean_dec(arr);
    return handle_retry_error(bio_);
  }
  lean_sarray_set_size(arr, read_bytes);
  return lean_io_result_mk_ok(arr);
}

// @& BIO -> ByteArray -> IO Unit
extern "C" lean_obj_res bio_write(b_lean_obj_arg bio, lean_obj_arg bs)
{
  auto bio_ = unwrapEC<BIO *>(bio);
  size_t written = 0;
  ERR_clear_error();
  if (!BIO_write_ex(bio_, lean_sarray_cptr(bs), lean_sarray_size(bs), &written))
  {
    lean_dec(bs);
    return handle_retry_error(bio_);
  }
  lean_dec(bs);
  return lean_io_result_mk_ok(lean_box(0));
}

// @& BIO -> IO Unit
extern "C" lean_obj_res bio_flush(b_lean_obj_arg bio)
{
  auto bio_ = unwrapEC<BIO *>(bio);
  ERR_clear_error();
  if (BIO_flush(bio_) != 1)
  {
    return handle_retry_error(bio_);
  }
  return lean_io_result_mk_ok(lean_box(0));
}

// @& BIO -> BaseIO Bool
extern "C" uint8_t bio_should_retry(b_lean_obj_arg bio) {
  auto bio_ = unwrapEC<BIO *>(bio);
  uint8_t t = BIO_should_retry(bio_);
  return !!t; // normalize to {0, 1}, which is Lean 4 `Bool`
}

// @& BIO -> BaseIO Bool
extern "C" uint8_t bio_should_write(b_lean_obj_arg bio) {
  auto bio_ = unwrapEC<BIO *>(bio);
  uint8_t t = BIO_should_write(bio_);
  return !!t; // normalize to {0, 1}, which is Lean 4 `Bool`
}

// @& BIO -> BaseIO Bool
extern "C" uint8_t bio_should_read(b_lean_obj_arg bio) {
  auto bio_ = unwrapEC<BIO *>(bio);
  uint8_t t = BIO_should_read(bio_);
  return !!t; // normalize to {0, 1}, which is Lean 4 `Bool`
}

// IO BIO
extern "C" lean_obj_res bio_mem() {
  SSL_FALLIBLE_NULL_ON_ERROR_IO_EC(BIO_new(BIO_s_mem()));
}

// IO BIO
extern "C" lean_obj_res bio_buffer() {
  SSL_FALLIBLE_NULL_ON_ERROR_IO_EC(BIO_new(BIO_f_buffer()));
}

// IO BIO
extern "C" lean_obj_res bio_base64() {
  SSL_FALLIBLE_NULL_ON_ERROR_IO_EC(BIO_new(BIO_f_base64()));
}

// @& SSLContext -> String -> IO Unit
extern "C" lean_obj_res ssl_ctx_load_verify_file(b_lean_obj_arg ctx, lean_obj_arg path) {
  SSL_CTX * ctx_ = unwrapEC<SSL_CTX *>(ctx);
  ERR_clear_error();
  if (!SSL_CTX_load_verify_file(ctx_, lean_string_cstr(path))) {
    lean_dec(path);
    return lean_io_result_mk_error(error_to_io_user_error());
  }
  lean_dec(path);
  return lean_io_result_mk_ok(lean_box(0));
}

// @& BIO -> IO Unit
extern "C" lean_obj_res bio_handshake(b_lean_obj_arg bio) {
  BIO * bio_ = unwrapEC<BIO *>(bio);
  ERR_clear_error();
  if (BIO_do_handshake(bio_) != 1) {
    return handle_retry_error(bio_);
  }
  return lean_io_result_mk_ok(lean_box(0));
}

// @& BIO -> BaseIO Unit
extern "C" lean_obj_res bio_ssl_shutdown(b_lean_obj_arg bio) {
  BIO * bio_ = unwrapEC<BIO *>(bio);
  BIO_ssl_shutdown(bio_);
  return lean_box(0);
}

// Async T = BaseIO (Std.Internal.IO.Async.MaybeTask (Except IO.Error T))
