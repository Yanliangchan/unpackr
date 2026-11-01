# Managed (.NET) assemblies

`internal/formats/dotnet` reads the CLR header and the ECMA-335 metadata
(streams, heaps and tables) of PE files that have one. It reads names and
references; it does not decode IL, decompile or run anything. All counts and
offsets are checked against the file and capped (see the constants at the top
of the package), and it is exercised by truncating and corrupting a real
assembly thousands of ways.

## What is reported

* metadata version, CLR flags (IL-only, strong-name signed, native entry point),
  entry-point token, stream list;
* assembly name and version, module name, assembly references;
* counts of types, methods, fields, member references, P/Invoke declarations and
  resources;
* P/Invoke declarations (native module and function) and the `Type.Member`
  pairs the code refers to. Both are added to the import list (the latter under
  the pseudo-library ".NET references"), so the capability rules apply to
  managed code: `Process.Start`, `WebClient.DownloadString`, `Assembly.Load`,
  `Convert.FromBase64String` with a decryptor, and so on. These are inferences
  from references, not observed behaviour;
* manifest resources with size, entropy and a type guess (PE, zip, gzip);
* name statistics (how many names are unreadable or one or two characters long)
  and how many methods have no IL in the file.

## Concealment signals

Each is a property of the tables and says what it saw. None names a protector.

| Signal | Condition | Strength |
|---|---|---|
| unreadable names | at least 50 names and a quarter contain control or non-ASCII characters | moderate |
| tiny names | at least 100 names and 70% are one or two characters | weak |
| missing method bodies | at least 20 methods, an entry point, and half of the methods have no IL in the file | moderate |
| embedded executable | a resource of 32 KB or more that begins with an MZ header | moderate |
| high-entropy resource | a resource of 64 KB or more with entropy 7.5 or more | weak (entropy family: cannot decide alone) |

Two independent families of moderate strength give `likely-packed`; the report
does not name a tool unless a known marker string is present.

## Verification

* Layout checked against two genuine assemblies (a C++/CLI plug-in and a
  reference `mscorlib`) using the standard library's PE reader as an independent
  view: type, method, field, member-reference and assembly-reference counts and
  names agree.
* A hand-built assembly (row sizes written out from the specification, not from
  the parser's schema) covers P/Invoke names, member references, resources and
  the method-body count.
* Control: the real plug-in is not flagged as packed or obfuscated.

## Not covered

No real obfuscated .NET sample was available, because this environment has no
.NET toolchain and no such sample was supplied. The concealment thresholds above
are reasoned from how renaming and body-hiding protectors behave, not tuned on
a corpus, and are marked as such. Not done: IL decoding, string-heap analysis of
the `#US` user strings (encrypted-string detection), resource decryption,
generic-instantiation and nested-type name resolution in member references, and
portable PDB tables.
