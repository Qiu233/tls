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

/--
Given a Lean module named `M.lean`, build a C shim named `M.shim.c`
-/
@[inline] private def buildCO (mod : Module) (shouldExport : Bool) : FetchM (Job FilePath) := do
  let cFile := mod.srcPath "shim.c"
  let irCFile := mod.irPath "shim.c"
  let cJob ← -- get or create shim.c file (we no shim.c is found, create an empty one to make lake happy)
    if (← cFile.pathExists) then
      proc { cmd := "cp", args := #[cFile.toString, irCFile.toString]}
      inputTextFile irCFile
    else
      logVerbose s!"creating empty shim.c file at {irCFile}"
      let _<-  proc { cmd := "touch", args := #[irCFile.toString] }
      inputTextFile irCFile

  let oFile := mod.irPath s!"shim.c.o.{if shouldExport then "export" else "noexport"}"
  let weakArgs := #["-I", (← getLeanIncludeDir).toString] ++ mod.weakLeancArgs
  let leancArgs := if shouldExport then mod.leancArgs.push "-DLEAN_EXPORTING" else mod.leancArgs
  buildO oFile cJob weakArgs leancArgs "cc"

module_facet shim.c.o.export mod : FilePath := buildCO mod true
module_facet shim.c.o.noexport mod : FilePath :=  buildCO mod false

@[default_target]
lean_lib «Tls» where
  nativeFacets := fun shouldExport =>
    #[if shouldExport then Module.oExportFacet else Module.oFacet,
      if shouldExport then {name := `module.shim.c.o.export, data_eq := Lake.FacetOut.module.shim.c.o.export}
      else {name := `module.shim.c.o.noexport, data_eq := Lake.FacetOut.module.shim.c.o.noexport}]

lean_exe "tls" where
  root := `Main
  supportInterpreter := true
