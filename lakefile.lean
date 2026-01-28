import Lake
open Lake DSL System

package "tls" where
  version := v!"0.1.0"
  precompileModules := true
  -- Actually we don't need this if there is already a system-wide openssl installation.
  -- TODO: get ssl library from environment variables.
  -- moreLinkArgs := #[
  --   "-lssl",
  --   "-L???"
  -- ]

/-!
Credit to https://gist.github.com/ydewit/7ab62be1bd0fea5bd53b48d23914dd6b#lake-configuration.
With some slight changes.
-/

@[always_inline]
private def shimName := "shim"

private def copyTextFile (file target_ : FilePath) : FetchM (Job FilePath) := do
  let fileJob ← inputTextFile file
  fileJob.bindM fun src => do
    proc { cmd := "cp", args := #[src.toString, target_.toString]}
    inputTextFile target_

private def createEmptyTextFile (target_ : FilePath) : FetchM (Job FilePath) := do
  if ← target_.pathExists then
    proc { cmd := "truncate", args := #["-s", "0", target_.toString] } -- clear the content
  else
    proc { cmd := "touch", args := #[target_.toString] }
  inputTextFile target_

/--
Given a Lean module named `M.lean`, build a C shim named `M.shim.c`
-/
private def buildCO (mod : Module) (shouldExport : Bool) : FetchM (Job FilePath) := do
  let cFile := mod.srcPath s!"{shimName}.c"
  let irCFile := mod.irPath s!"{shimName}.c"
  let cJob ← -- get or create shim.c file (we no shim.c is found, create an empty one to make lake happy)
    if (← cFile.pathExists) then
      copyTextFile cFile irCFile
    else
      logVerbose s!"creating empty shim.c file at {irCFile}"
      createEmptyTextFile irCFile
  let oFile := mod.irPath s!"shim.c.o.{if shouldExport then "export" else "noexport"}"
  let weakArgs := #["-I", (← getLeanIncludeDir).toString, "-fPIC"] ++ mod.weakLeancArgs
  let leancArgs := if shouldExport then mod.leancArgs.push "-DLEAN_EXPORTING" else mod.leancArgs
  buildO oFile cJob weakArgs leancArgs "cc"

private def buildCPPO (mod : Module) (shouldExport : Bool) : FetchM (Job FilePath) := do
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
  let weakArgs := #["-I", (← getLeanIncludeDir).toString, "-fPIC"] ++ mod.weakLeancArgs
  let leancArgs := if shouldExport then mod.leancArgs.push "-DLEAN_EXPORTING" else mod.leancArgs
  buildO oFile cJob weakArgs leancArgs "cc"

module_facet shim.c.o.export mod : FilePath := buildCO mod true
module_facet shim.c.o.noexport mod : FilePath := buildCO mod false

module_facet shim.cpp.o.export mod : FilePath := buildCPPO mod true
module_facet shim.cpp.o.noexport mod : FilePath := buildCPPO mod false

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
