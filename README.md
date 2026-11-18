# `aselinux` - Android SELinux rules research tool

Tools to explore an Android SELinux policy (in `magiskpolicy --print-rules` format) and its `*_contexts`
files.

The workspace contains:

- **`selinux_parser`**: parsers (built on `nom`) for
  - `magiskpolicy` rules (`rules.te`);
  - `file_contexts`: maps path regexes to contexts, with an optional file type;
  - `property_contexts`: maps system property names or prefixes to a context.
- **`segui`**: an exploration GUI built on top of these parsers.

## `segui` — exploration GUI

<img src="assets/logo.png" alt="segui logo" width="96">

```sh
cargo run --release -p segui -- rules.te selinux/plat_file_contexts selinux/plat_property_contexts
```
