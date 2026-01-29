#pragma once

#include <lean/lean.h>
#include <openssl/ssl.h>

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

// smart pointer of lean object
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
  ~LeanObjRef() { lean_dec(this->m_ptr); this->m_ptr = lean_box(0); }
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
  void steal_drop() {
    lean_dec(this->steal());
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
