module

public import Lean

public meta section

namespace Tls.Internal

open Lean Elab Parser Term Command

syntax (name := Parser.ffi_type) declModifiers "declare_ffi_type% " rawIdent typeSpec : command

@[command_elab Parser.ffi_type]
def elabFFIType : CommandElab := fun stx => do
  let `(Parser.ffi_type| $mods:declModifiers declare_ffi_type% $name:ident : $type) := stx | throwUnsupportedSyntax
  let typeE ← runTermElabM fun _ => elabType type
  if typeE.hasMVar then
    throwErrorAt type "type cannot contain metavariables"
  let sort ← match typeE with
    | .sort level => pure level
    | _ => throwErrorAt type "type must be a universe"
  if sort == Level.zero then
    throwErrorAt type "`Sort 0` is not allowed here"
  let sort ← match sort with
    | .succ x => pure x
    | .param .. => throwErrorAt type "type cannot be polymorphic"
    | _ => throwErrorAt type "type must be deterministic"
  let pname := mkIdentFrom name <| name.getId.appendAfter "_impl"
  let nempty ← `(private opaque $pname : NonemptyType.{$(quote sort)})
  let decl ← `($mods:declModifiers def $name : $type := NonemptyType.type $pname)
  let mods' ← elabModifiers mods
  let vis ← match mods'.visibility with
    | .regular => pure none
    | .private => some <$> `(visibility| private)
    | .public => some <$> `(visibility| public)
  let inst ← `($[$vis:visibility]? instance : Nonempty $name := by exact $(pname).property)
  elabCommand nempty
  elabCommand decl
  elabCommand inst
