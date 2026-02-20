-- module

import Tls
import Http.Client
import Std

open Std.Internal.IO.Async

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
  let tlsCfg : TLSClientConfig :=
    { serverName? := some "localhost"
      caCertFile? := some "/home/qiu/dummyweb/.nginx/ssl/self.crt"
      alpnProtocols := #["h2", "http/1.1"]
      requireALPN? := some "h2" }
  let client : Http.HttpClient :=
    { host := "127.0.0.1", port := 8443, transport := tls_transport tlsCfg, protocol := .http2 }
  let resp ← client.getAsync "/" |>.wait
  println! "!{repr resp}"
