#include <openssl/ssl.h>
#include <openssl/err.h>
#include <lean/lean.h>
#include <string>
#include <vector>
#include <functional>
#include <optional>

#define EXTERNAL_CLASS_NAME(NAME) g_##NAME##_external_class
#define DECLARE_EXTERNAL_CLASS(NAME) static lean_external_class *EXTERNAL_CLASS_NAME(NAME) = NULL;

template <typename T>
lean_object *wrapEC(T);
template <typename T>
T unwrapEC(lean_object *);

#define DECLARE_EXTERNAL_CLASS_WRAPEER(NAME, TYPE)                      \
  template <>                                                           \
  lean_object *wrapEC<TYPE>(TYPE obj)                                   \
  {                                                                     \
    return lean_alloc_external(EXTERNAL_CLASS_NAME(NAME), (void *)obj); \
  }

#define DECLARE_EXTERNAL_CLASS_UNWRAPEER(NAME, TYPE)       \
  template <>                                              \
  TYPE unwrapEC<TYPE>(lean_object * obj)                   \
  {                                                        \
    return static_cast<TYPE>(lean_get_external_data(obj)); \
  }

#define SIMPLE_EXTERNAL_CLASS(NAME, TYPE)    \
  DECLARE_EXTERNAL_CLASS(NAME)               \
  DECLARE_EXTERNAL_CLASS_WRAPEER(NAME, TYPE) \
  DECLARE_EXTERNAL_CLASS_UNWRAPEER(NAME, TYPE)

SIMPLE_EXTERNAL_CLASS(ssl_method, const SSL_METHOD *);
SIMPLE_EXTERNAL_CLASS(ssl_ctx, SSL_CTX *);

class LeanObjRef {
private:
  lean_object * m_ptr;
public:
  LeanObjRef(const LeanObjRef & other) {
    this->m_ptr = other.m_ptr;
    lean_inc(this->m_ptr);
  }
  // LeanObjRef(const LeanObjRef & other) = delete;
  LeanObjRef & operator=(const LeanObjRef & other) {
    if (this->m_ptr == other.m_ptr) {
      return *this;
    }
    lean_dec(this->m_ptr);
    this->m_ptr = other.m_ptr;
    lean_inc(other.m_ptr);
    return *this;
  }
  // LeanObjRef & operator=(const LeanObjRef & other) = delete;
  LeanObjRef():m_ptr(lean_box(0)) {}
  LeanObjRef(lean_obj_arg moved):m_ptr(moved) {}
  ~LeanObjRef() { lean_dec(this->m_ptr); }
  b_lean_obj_res get() { return this->m_ptr; }
  operator b_lean_obj_res() const {
    return this->m_ptr;
  }
  void swap(LeanObjRef & x) {
    auto r = this->m_ptr;
    this->m_ptr = x.m_ptr;
    x.m_ptr = r;
  }
  lean_obj_res steal() {
    auto r = this->m_ptr;
    this->m_ptr = lean_box(0);
    return r;
  }
  bool is_unit() {
    return lean_is_scalar(this->m_ptr) && lean_unbox(this->m_ptr) == 0;
  }
  // move constructor
  LeanObjRef(LeanObjRef && other) { this->m_ptr = other.steal(); }
  static LeanObjRef inc(b_lean_obj_arg ptr) {
    lean_inc(ptr);
    return LeanObjRef(ptr);
  }
  LeanObjRef task_get() {
    return LeanObjRef::inc(lean_task_get(this->m_ptr));
  }
  LeanObjRef ctor_get(unsigned int i) {
    return LeanObjRef::inc(lean_ctor_get(this->m_ptr, i));
  }
  LeanObjRef dup() {
    lean_inc(this->m_ptr);
    return LeanObjRef(this->m_ptr);
  }
};

static_assert(sizeof(LeanObjRef) == sizeof(void*));

class LeanBIO {
private:
  BIO * m_bio;
  LeanObjRef m_tail;
  // `BIO_push(a, b)` will make `a` owns `b`. We must call `lean_dec` on `b` when it is done.
public:
  LeanBIO(const LeanBIO&) = delete;
  LeanBIO& operator=(const LeanBIO&) = delete;
  BIO * get() { return this->m_bio; }
  // will override last tail
  void set_tail(const LeanObjRef & tail) {
    this->m_tail = tail;
  }
  LeanBIO() = delete;
  LeanBIO(BIO * bio) : m_bio(bio) {}
  ~LeanBIO() {
    BIO_free(this->m_bio);
  }
};

SIMPLE_EXTERNAL_CLASS(bio, LeanBIO *);

// IO SSLMethod
extern "C" lean_object *ssl_tls_method()
{
  const SSL_METHOD *method = TLS_method();
  return lean_io_result_mk_ok(lean_alloc_external(EXTERNAL_CLASS_NAME(ssl_method), (void *)method));
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

// template <typename T, lean_object *(*wrap)(T) = [](T t)
//                       { return lean_box(0); }>
// lean_object *ssl_fallible_io_null_on_error(std::function<T()> f)
// {
//   ERR_clear_error();
//   auto res = f();
//   if (!res)
//   {
//     return lean_io_result_mk_error(error_to_io_user_error());
//   }
//   return lean_io_result_mk_ok(wrap(res));
// }

// template <typename T, lean_object *(*wrap)(T) = wrapEC<T>>
// lean_object *ssl_fallible_io_EC(std::function<T()> f)
// {
//   ssl_fallible_io_null_on_error<T, wrap>(f);
// }

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
  ERR_clear_error();
  SSL_FALLIBLE_NULL_ON_ERROR_IO_EC(SSL_CTX_new(meth));
}

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
        auto bio = static_cast<LeanBIO *>(ptr);
        delete bio; }, [](void *obj, lean_object *fn) {});
  return lean_io_result_mk_ok(lean_box(0));
}

//

class LeanStreamCtx
{
public:
  LeanObjRef stream;
  LeanObjRef pending_read_task;
  LeanObjRef pending_send_task;
  size_t pending_send_len;
  LeanObjRef pending_flush_task;
  LeanStreamCtx(LeanObjRef s) : stream(s) {}
  void drop_read_task() {
    lean_dec(this->pending_read_task.steal());
  }
  void drop_send_task() {
    lean_dec(this->pending_send_task.steal());
  }
  void drop_flush_task() {
    lean_dec(this->pending_flush_task.steal());
  }
};

typedef struct StreamOps
{
  // Return values convention (you choose; this example uses):
  //   1 = success, 0 = would-block/try again, -1 = fatal error (set *err)
  std::unique_ptr<LeanStreamCtx> ctx;
  std::function<int(LeanStreamCtx *ctx, unsigned char *buf, size_t len, size_t *out_n, int *err)> read;
  std::function<int(LeanStreamCtx *ctx, const unsigned char *buf, size_t len, size_t *out_n, int *err)> write;
  std::function<int(LeanStreamCtx *ctx, int *err)> flush;
  //   StreamOps() = delete;
  // TODO: remove default constructor
} StreamOps;

typedef struct StreamBioState
{
  StreamOps ops;
  int last_err; // for debugging
} StreamBioState;

static int streambio_create(BIO *b)
{
  BIO_set_data(b, NULL); // we'll set data after BIO_new()
  return 1;
}

static int streambio_destroy(BIO *b)
{
  if (b == NULL)
    return 0;
  StreamBioState *st = (StreamBioState *)BIO_get_data(b);
  delete st;
  BIO_set_data(b, NULL);
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
  int err = 0;
  int rc = st->ops.read(st->ops.ctx.get(), (unsigned char *)out, outl, &n, &err);
  st->last_err = err;

  if (rc == 1)
  {
    if (readbytes)
      *readbytes = n;
    return 1; // success
  }
  if (rc == 0)
  {
    // would-block / try again later
    BIO_set_retry_read(b);
    return 0;
  }
  // fatal
  return 0;
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
  int err = 0;
  int rc = st->ops.write(st->ops.ctx.get(), (const unsigned char *)in, inl, &n, &err);
  st->last_err = err;

  if (rc == 1)
  {
    if (written)
      *written = n;
    return 1;
  }
  if (rc == 0)
  {
    BIO_set_retry_write(b);
    return 0;
  }
  return 0;
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
      int err = 0;
      int rc = st->ops.flush(st->ops.ctx.get(), &err);
      st->last_err = err;
      return (rc == 1) ? 1 : 0;
    }
    return 1; // "no-op flush" is acceptable if flushing unnecessary

  default:
    return 0;
  }
}

static BIO_METHOD *streambio_method(const char *name)
{
  static BIO_METHOD *m = NULL;
  if (m != NULL)
    return m;

  // type: source/sink is appropriate for a transport BIO
  m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, name);
  assert(m != NULL);
  if (!m)
    return NULL;

  BIO_meth_set_create(m, streambio_create);
  BIO_meth_set_destroy(m, streambio_destroy);
  BIO_meth_set_read_ex(m, streambio_read_ex);
  BIO_meth_set_write_ex(m, streambio_write_ex);
  BIO_meth_set_ctrl(m, streambio_ctrl);
  return m;
}

static BIO *BIO_new_stream(StreamBioState *state)
{
  BIO_METHOD *m = streambio_method("lean-bio");
  if (!m)
    return NULL;
  BIO *b = BIO_new(m);
  if (!b)
    return NULL;
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

static int poll_unit_task(LeanObjRef & task, int *err)
{
  if (task.is_unit())
    return 1; // no pending task

  uint8_t st = lean_io_get_task_state_core(task); // 0 running, 1 finished, 2 aborted
  if (st == 0)
  {
    *err = EAGAIN;
    return 0; // would-block
  }
  if (st == 2)
  {
    *err = EIO;
    LeanObjRef tmp;
    task.swap(tmp);
    return -1; // fatal
  }

  // finished
  LeanObjRef except = task.task_get(); // blocks only if not finished
  LeanObjRef tmp;
  task.swap(tmp);

  if (lean_obj_tag(except) == 0)
  { // Except.error
    *err = EIO;
    return -1;
  }
  else
  { // Except.ok Unit
    return 1;
  }
}

static int lean_read(LeanStreamCtx *ctx, unsigned char *buf, size_t len, size_t *out_n, int *err)
{
  if (!ctx->pending_read_task.is_unit())
  {
    uint8_t st = lean_io_get_task_state_core(ctx->pending_read_task);
    if (st != /*finished*/ 2)
    {                // see note below
      *err = EAGAIN; // would-block
      return 0;
    }
    LeanObjRef except = ctx->pending_read_task.task_get();
    ctx->drop_read_task();

    // Handle Except
    if (lean_obj_tag(except) == 0)
    { // Except.error
      *err = EIO;
      return -1;
    }
    else
    {
      LeanObjRef bs = except.ctor_get(0);
      size_t n = lean_sarray_size(bs);
      if (n > len)
        n = len; // TODO: throw error? The stream implementation cannot return more than requested.
      memcpy(buf, lean_sarray_cptr(bs), n);
      *out_n = n;
      return 1; // success
    }
  }
  LeanObjRef recv = ctx->stream.ctor_get(0);              // USize → Async ByteArray
  lean_inc(recv);
  LeanObjRef bs_async(lean_apply_1(recv, lean_box(len))); // Async ByteArray
  LeanObjRef maybe = unwrap_base_io(bs_async);            // Std.Internal.IO.Async.MaybeTask (Except IO.Error ByteArray)

  if (lean_obj_tag(maybe) == 0)
  { // MaybeTask.pure
    LeanObjRef except = maybe.ctor_get(0); // Except ...

    // same Except handling as above
    if (lean_obj_tag(except) == 0)
    {
      *err = EIO;
      return -1;
    }
    else
    {
      LeanObjRef bs = except.ctor_get(0);
      size_t n = lean_sarray_size(bs);
      if (n > len)
        n = len;
      memcpy(buf, lean_sarray_cptr(bs), n);
      *out_n = n;
      return 1;
    }
  }
  else
  { // MaybeTask.ofTask
    LeanObjRef task = maybe.ctor_get(0); // Task (Except ...)
    ctx->pending_read_task.swap(task); // stash it
    *err = EAGAIN;            // would-block
    return 0;
  }
}

// template <typename T>
// static T discr_maybe_task(
//     LeanObjRef maybe_task,
//     std::function<T(LeanObjRef val)> onVal,
//     std::function<T(LeanObjRef task)> onTask)
// {
//   auto tag = lean_obj_tag(maybe_task);
//   LeanObjRef inner = maybe_task.ctor_get(0);
//   if (tag == 0) {
//     return onVal(inner);
//   } else {
//     return onTask(inner);
//   }
// }

static int lean_write(LeanStreamCtx *ctx, const unsigned char *buf, size_t len,
                      size_t *out_n, int *err)
{
  *out_n = 0;

  // If we already have a pending send task, just poll it.
  if (!ctx->pending_send_task.is_unit())
  {
    int r = poll_unit_task(ctx->pending_send_task, err);
    if (r == 1)
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
      *err = EIO;
      *out_n = 0;
      return -1;
    }
    else
    { // ok
      *err = 0;
      *out_n = len;
      return 1;
    }
  } else {
    // stash it and report would-block
    ctx->pending_send_task.swap(inner);
    ctx->pending_send_len = len;

    *err = EAGAIN;
    *out_n = 0;
    return 0;
  }
}

static int lean_flush(LeanStreamCtx *ctx, int *err)
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
      *err = EIO;
      return -1;
    }
    else
    {
      *err = 0;
      return 1;
    }
  } else {
    ctx->pending_flush_task.swap(inner);
    *err = EAGAIN;
    return 0;
  }
}

// Stream -> IO BIO
extern "C" lean_obj_res bio_of_stream(lean_obj_arg stream)
{
  std::unique_ptr<LeanStreamCtx> ctx = std::make_unique<LeanStreamCtx>(std::move(LeanStreamCtx(LeanObjRef(stream))));
  StreamBioState *st = new StreamBioState{StreamOps{std::move(ctx), lean_read, lean_write, lean_flush}, 0};
  SSL_FALLIBLE_NULL_ON_ERROR_IO_EC(new LeanBIO(BIO_new_stream(st)));
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

// Unit -> BaseIO SSLError
// static lean_obj_res make_ssl_error_bio_retry() {
//   auto c = lean_alloc_ctor(1, 0, 0);
//   return c;
// }

// // Array String -> BaseIO SSLError
// static lean_obj_res make_ssl_error_hard(lean_obj_arg errs) {
//   auto c = lean_alloc_ctor(0, 1, 0);
//   lean_ctor_set(c, 0, errs);
//   return c;
// }

// IO (BIO × BIO)
extern "C" lean_obj_res bio_new_pair()
{
  BIO *b1, *b2;
  ERR_clear_error();
  if (!BIO_new_bio_pair(&b1, 0, &b2, 0))
  {
    return lean_io_result_mk_error(error_to_io_user_error());
  }
  LeanBIO * b1__ = new LeanBIO(b1);
  LeanBIO * b2__ = new LeanBIO(b2);
  auto b1_ = wrapEC<LeanBIO *>(b1__);
  auto b2_ = wrapEC<LeanBIO *>(b2__);
  auto pair = lean_alloc_ctor(0, 2, 0); // Prod.mk
  lean_ctor_set(pair, 0, b1_);
  lean_ctor_set(pair, 1, b2_);
  return lean_io_result_mk_ok(pair);
}

// BIO -> BIO -> BaseIO BIO
extern "C" lean_obj_res bio_push(lean_obj_arg a, lean_obj_arg b)
{
  auto a_ = unwrapEC<LeanBIO *>(a);
  auto b_ = unwrapEC<LeanBIO *>(b);
  auto r = BIO_push(a_->get(), b_->get());
  assert(a_->get() == r);
  a_->set_tail(LeanObjRef(b));
  return a; // According to https://docs.openssl.org/1.1.1/man3/BIO_push, `BIO_push` returns its first argument.
}

// @& SSLContext -> Int32 -> IO BIO
extern "C" lean_obj_res bio_ssl(b_lean_obj_arg ctx, int client)
{
  auto ctx_ = unwrapEC<SSL_CTX *>(ctx);
  SSL_FALLIBLE_NULL_ON_ERROR_IO_EC(new LeanBIO(BIO_new_ssl(ctx_, client)));
}

// @& BIO -> USize -> IO ByteArray
extern "C" lean_obj_res bio_read(b_lean_obj_arg bio, size_t len)
{
  auto bio_ = unwrapEC<LeanBIO *>(bio);
  auto arr = lean_alloc_sarray(1, 0, len); // ByteArray
  size_t read_bytes = 0;
  if (!BIO_read_ex(bio_->get(), lean_sarray_cptr(arr), len, &read_bytes))
  {
    return lean_io_result_mk_error(error_to_io_user_error());
  }
  lean_sarray_set_size(arr, read_bytes);
  return lean_io_result_mk_ok(arr);
}

// @& BIO -> ByteArray -> IO Unit
extern "C" lean_obj_res bio_write(b_lean_obj_arg bio, lean_obj_arg bs)
{
  auto bio_ = unwrapEC<LeanBIO *>(bio);
  size_t written = 0;
  if (!BIO_write_ex(bio_->get(), lean_sarray_cptr(bs), lean_sarray_size(bs), &written))
  {
    return lean_io_result_mk_error(error_to_io_user_error());
  }
  lean_dec(bs);
  return lean_io_result_mk_ok(lean_box(0));
}

// @& BIO -> IO Unit
extern "C" lean_obj_res bio_flush(b_lean_obj_arg bio)
{
  auto bio_ = unwrapEC<LeanBIO *>(bio);
  if (BIO_flush(bio_->get()) != 1)
  {
    return lean_io_result_mk_error(error_to_io_user_error());
  }
  return lean_io_result_mk_ok(lean_box(0));
}

// @& BIO -> BaseIO Bool
extern "C" uint8_t bio_should_retry(b_lean_obj_arg bio) {
  auto bio_ = unwrapEC<LeanBIO *>(bio);
  uint8_t t = BIO_should_retry(bio_->get());
  return !!t; // normalize to {0, 1}, which is Lean 4 `Bool`
}

// @& BIO -> BaseIO Bool
extern "C" uint8_t bio_should_write(b_lean_obj_arg bio) {
  auto bio_ = unwrapEC<LeanBIO *>(bio);
  uint8_t t = BIO_should_write(bio_->get());
  return !!t; // normalize to {0, 1}, which is Lean 4 `Bool`
}

// @& BIO -> BaseIO Bool
extern "C" uint8_t bio_should_read(b_lean_obj_arg bio) {
  auto bio_ = unwrapEC<LeanBIO *>(bio);
  uint8_t t = BIO_should_read(bio_->get());
  return !!t; // normalize to {0, 1}, which is Lean 4 `Bool`
}


// Async T = BaseIO (Std.Internal.IO.Async.MaybeTask (Except IO.Error T))

