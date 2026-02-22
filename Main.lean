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
  let client : Http.HttpClient := .mkTLS "localhost" (port := 8443) (verify_peer := false)
  let resp ← client.getAsync "/" |>.wait
  println! "!{repr resp}"
