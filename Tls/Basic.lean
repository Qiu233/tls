import Tls.FFI
import Std

#check Std.Internal.IO.Async.TCP.Socket.Client.send
#check Std.Internal.IO.Async.TCP.Socket.Client
#check Std.Internal.UV.TCP.Socket
#check Std.Internal.UV.TCP.Socket
-- #check Std.Internal.UV.System
-- def hello := "world"

-- #eval Tls.FFI.test (pure ⟨#[1]⟩)

open Tls.FFI
open Std.Internal.IO.Async

def f : Async Unit := do
  IO.FS.withFile "a.txt" .write fun handle => do
    let recv : USize → Async ByteArray := fun size => do
      handle.read size
    let send : ByteArray → Async Unit := fun bs => do
      println! "????"
      handle.write bs
    let flush : Async Unit := handle.flush
    let s : Stream := { recv, send, flush }
    let outBIO ← BIO.ofStream s
    println! "outBIO created"
    let (a, b) ← BIO.mkPair
    println! "BIO pair created"
    let _b ← b.push outBIO
    println! "BIO push success"
    a.write (String.toUTF8 "hello")
    -- send (String.toUTF8 "hello") |>.wait

-- #eval f.wait

-- #check async

-- #synth MonadLift IO Async
