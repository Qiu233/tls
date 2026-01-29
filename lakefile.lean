import Lake
open Lake DSL System

open Lean Elab Command in
elab "#find_multiarch" : command => do
  -- try discard <| IO.Process.run { cmd := "pkg-config", args := #["--cflags", "--libs", "openssl"] }
  -- catch _ => throwError "openssl installation is absent"
  try discard <| IO.Process.run { cmd := "gcc", args := #["--version"] }
  catch _ => throwError "gcc installation is absent"
  let triplet ← try IO.Process.run { cmd := "gcc", args := #["-print-multiarch"] }
    catch _ => throwError "impossible: gcc -print-multiarch failed"
  let triplet := triplet.trimAscii -- remove trailing linebreak
  let library_path1 := s!"/usr/lib/{triplet}"
  let library_path2 := s!"/lib/{triplet}"
  let a1 := quote (k := `str) library_path1
  let a2 := quote (k := `str) library_path2
  let id := mkIdent `path_multiarch_lib
  let code ← `(/-- the gcc -multiarch library path to pass as -L arguments -/
    def $id : Array String := #[$a1, $a2])
  elabCommand code

#find_multiarch

/- Copied from https://github.com/T-Brick/DateTime/blob/main/lakefile.lean -/
/-- Compute the path to `libstdc++.so.6` by running `whereis` -/
elab "#get_libstdcpp" : command =>
  open Lean Elab Command Term in do
  let defLib (term : Expr) :=
    liftTermElabM <| addAndCompile <| Declaration.defnDecl {
        name := `libstdcpp
        levelParams := []
        type := mkApp (mkConst ``Option [.zero]) (mkConst ``System.FilePath)
        value := term
        hints := .abbrev
        safety := .safe
      }
  if System.Platform.isOSX then
    defLib (mkApp (mkConst ``none [.zero]) (mkConst ``System.FilePath))
    return
  let output ← IO.Process.run {
    cmd := "whereis"
    args := #["libstdc++.so.6"]
  }
  let xs := output.split (·.isWhitespace) |>.toList (β := String.Slice) |>.map fun x => x.toString
  if xs.length < 2 then
    logError ("whereis output malformed:\n" ++ output)
  -- let name := xs[0]!
  let loc := xs[1]!
  -- logInfo s!"found {name} at {loc}"
  defLib (mkAppN (mkConst ``some [.zero]) #[
    mkConst ``System.FilePath,
    mkApp (mkConst ``System.FilePath.mk) (mkStrLit loc)])

#get_libstdcpp -- now available as `libstdcpp` declaration

package "tls" where
  version := v!"0.1.0"
  precompileModules := true
  moreLinkArgs := #[
    match libstdcpp with | none => "" | some x => x.toString,
    "-lssl",
    "-lcrypto",
  ]

/-!
Credit to https://gist.github.com/ydewit/7ab62be1bd0fea5bd53b48d23914dd6b#lake-configuration.
With some slight changes.
-/

@[always_inline]
private def shimName := "shim"

private def copyTextFile (file target_ : FilePath) : FetchM (Job FilePath) := do
  let fileJob ← inputTextFile file
  fileJob.bindM fun src => do
    createParentDirs target_
    proc { cmd := "cp", args := #[src.toString, target_.toString]}
    inputTextFile target_

private def createEmptyTextFile (target_ : FilePath) : FetchM (Job FilePath) := do
  createParentDirs target_
  if ← target_.pathExists then
    proc { cmd := "truncate", args := #["-s", "0", target_.toString] } -- clear the content
  else
    proc { cmd := "touch", args := #[target_.toString] }
  inputTextFile target_

/--
Given a Lean module named `M.lean`, build a C shim named `M.shim.c`
-/
private def buildCO (mod : Module) (hJob : Job FilePath) (shouldExport : Bool) : FetchM (Job FilePath) := do
  let cFile := mod.srcPath s!"{shimName}.c"
  let irCFile := mod.irPath s!"{shimName}.c"
  let cJob ←
    if (← cFile.pathExists) then
      copyTextFile cFile irCFile
    else
      logVerbose s!"creating empty shim.c file at {irCFile}"
      createEmptyTextFile irCFile
  let oFile := mod.irPath s!"shim.c.o.{if shouldExport then "export" else "noexport"}"
  let weakArgs := #["-I", (← getLeanIncludeDir).toString, "-fPIC"] ++ mod.weakLeancArgs
  let leancArgs := if shouldExport then mod.leancArgs.push "-DLEAN_EXPORTING" else mod.leancArgs
  let job := hJob.zipWith (fun _ y => y) (other := cJob)
  buildO oFile job weakArgs leancArgs "cc"

private def buildCPPO (mod : Module) (hJob : Job FilePath) (shouldExport : Bool) : FetchM (Job FilePath) := do
  let cFile := mod.srcPath s!"{shimName}.cpp"
  let irCFile := mod.irPath s!"{shimName}.cpp"
  let cJob ←
    if (← cFile.pathExists) then
      copyTextFile cFile irCFile
    else
      logVerbose s!"creating empty shim.cpp file at {irCFile}"
      createEmptyTextFile irCFile
  let oFile := mod.irPath s!"shim.cpp.o.{if shouldExport then "export" else "noexport"}"
  -- TODO: if you want to link with C++ standard library, add `-lstdc++`, `-I...`, and `-L...`
  let weakArgs := #["-I", (← getLeanIncludeDir).toString, "-fPIC", "-std=c++20"] ++ mod.weakLeancArgs
  let leancArgs := if shouldExport then mod.leancArgs.push "-DLEAN_EXPORTING" else mod.leancArgs
  let job := hJob.zipWith (fun _ y => y) (other := cJob)
  buildO oFile job weakArgs leancArgs "cc"

private def copyH (mod : Module) : FetchM (Job FilePath) := do
  let cFile := mod.srcPath s!"{shimName}.h"
  let irCFile := mod.irPath s!"{shimName}.h"
  if (← cFile.pathExists) then
    copyTextFile cFile irCFile
  else
    logVerbose s!"creating empty shim.h file at {irCFile}"
    createEmptyTextFile irCFile

module_facet shim.h mod : FilePath := copyH mod -- use this can prevent copying the header multiple times

module_facet shim.c.o.export mod : FilePath := do
  let job ← shim.h._modFacet.fetch mod
  buildCO mod job true

module_facet shim.c.o.noexport mod : FilePath := do
  let job ← shim.h._modFacet.fetch mod
  buildCO mod job false

module_facet shim.cpp.o.export mod : FilePath := do
  let job ← shim.h._modFacet.fetch mod
  buildCPPO mod job true

module_facet shim.cpp.o.noexport mod : FilePath := do
  let job ← shim.h._modFacet.fetch mod
  buildCPPO mod job false

@[default_target]
lean_lib «Tls» where
  nativeFacets := fun shouldExport =>
    #[if shouldExport then Module.oExportFacet else Module.oFacet,
      if shouldExport then {name := `module.shim.c.o.export, data_eq := Lake.FacetOut.module.shim.c.o.export}
      else {name := `module.shim.c.o.noexport, data_eq := Lake.FacetOut.module.shim.c.o.noexport},
      if shouldExport then {name := `module.shim.cpp.o.export, data_eq := Lake.FacetOut.module.shim.cpp.o.export}
      else {name := `module.shim.cpp.o.noexport, data_eq := Lake.FacetOut.module.shim.cpp.o.noexport},
    ]

lean_exe "tls" where
  root := `Main
  supportInterpreter := true

require http from git "https://github.com/Qiu233/http"
