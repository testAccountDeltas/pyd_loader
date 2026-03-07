# pyd_loader

Load `.pyd` (Cython/C-extension) files **directly from memory** on Windows — no temp files, no disk writes.

Built on top of [`pythonmemorymodule`](https://github.com/naksyn/pythonmemorymodule). Supports both single `.pyd` files and multi-file packages with relative imports (PEP 451 multi-phase init).

---

## Features

- Load `.pyd` from raw bytes (network, encrypted storage, archives, etc.)
- Supports **single-phase** and **multi-phase** (PEP 451) C-extension initialization
- Loads **packages** with relative imports (`from .parser import ...`)
- Module **inspection**: functions, classes, constants, imports
- **DLL-level inspection**: PE export/import tables (requires `pefile`)
- **Runtime import tracking**: intercept every `import` call with a callback
- Suppresses `DEBUG:` spam from `pythonmemorymodule` by default

---

## Requirements

```
pip install pythonmemorymodule
pip install pefile        # optional — needed for auto module name detection and DLL inspection
```

**Windows only.** `.pyd` files are Windows DLLs.

---

## Quick Start

### Load a single `.pyd`

```python
from pyd_loader import PydMemoryLoader

# From file path
loader = PydMemoryLoader.from_file("parser.cp312-win_amd64.pyd")
mod = loader.load()

# Direct call
result = mod.parse_pattern("E8 ? ? ? ?")
print(result)

# Available via import after load()
import parser
parser.parse_pattern("E8 ? ? ? ?")
```

### Load from bytes (no file on disk)

```python
from pyd_loader import PydMemoryLoader

with open("parser.cp312-win_amd64.pyd", "rb") as f:
    data = f.read()

loader = PydMemoryLoader(data, module_name="parser")
mod = loader.load()
```

### Load a package

```python
from pyd_loader import PydPackageLoader

# Option A — add files manually (explicit order)
loader = PydPackageLoader("atom")
loader.add_file("parser.cp312-win_amd64.pyd")
loader.add_file("reader.cp312-win_amd64.pyd")
loader.add_file("__init__.cp312-win_amd64.pyd")
pkg = loader.load()

# Option B — load entire directory
loader = PydPackageLoader.from_dir("atom", "./atom/")
pkg = loader.load()

# Use the package
import atom
result = atom.parse_pattern("E8 ? ? ? ?")
scanner = atom.FastPeScanner(data)
```

> **Note:** `__init__.pyd` is always loaded last automatically, regardless of the order you call `add_file()`. Submodules must be registered before `__init__` executes its relative imports.

---

## API Reference

### `PydMemoryLoader`

Loads a single `.pyd` file.

#### Constructor

```python
PydMemoryLoader(
    data: bytes,
    module_name: str | None = None,
    register_in_sys_modules: bool = True,
    verbose: bool = False,
    suppress_debug: bool = True,
)
```

| Parameter | Description |
|-----------|-------------|
| `data` | Raw bytes of the `.pyd` file |
| `module_name` | Module name to register. If `None`, auto-detected from DLL exports (requires `pefile`) |
| `register_in_sys_modules` | Whether to add to `sys.modules` after loading |
| `verbose` | Print internal loading steps |
| `suppress_debug` | Suppress `DEBUG:` output from `pythonmemorymodule` (default `True`) |

#### Class Methods

```python
PydMemoryLoader.from_file(
    path: str,
    module_name: str | None = None,
    suppress_debug: bool = True,
    **kwargs,
) -> PydMemoryLoader
```

Creates a loader from a file on disk.

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `load()` | `types.ModuleType` | Load the module. Repeated calls return the cached result |
| `list_attrs()` | `dict[str, dict]` | All public attributes: `{name: {type, category, value}}` |
| `list_functions()` | `dict[str, dict]` | Functions with signatures: `{name: {signature, doc, type}}` |
| `list_classes()` | `dict[str, dict]` | Classes with members: `{name: {bases, members, doc}}` |
| `list_constants()` | `dict[str, Any]` | Constants and variables: `{name: value}` |
| `list_imports()` | `dict[str, str]` | Modules visible in namespace: `{attr: full_module_name}` |
| `print_info()` | `None` | Print a full structured report to stdout |
| `print_dll_exports()` | `None` | Print the DLL export table (requires `pefile`) |
| `print_dll_imports()` | `None` | Print the DLL import table — PE-level dependencies (requires `pefile`) |
| `enable_import_tracking(callback=None)` | `None` | Start intercepting all `import` calls |
| `disable_import_tracking()` | `None` | Stop intercepting |
| `print_import_log(show_stack, only_new)` | `None` | Print intercepted import log |
| `clear_import_log()` | `None` | Clear the log |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `module` | `ModuleType \| None` | The loaded module, or `None` before `load()` |
| `import_log` | `list[ImportEvent]` | Raw list of intercepted import events |

---

### `PydPackageLoader`

Loads a multi-file package. Handles relative imports automatically.

#### Constructor

```python
PydPackageLoader(
    package_name: str,
    suppress_debug: bool = True,
    verbose: bool = False,
)
```

#### Class Methods

```python
PydPackageLoader.from_dir(
    package_name: str,
    directory: str,
    pattern: str = "*.pyd",
    **kwargs,
) -> PydPackageLoader
```

Loads all `.pyd` files from a directory.

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `add(module_name, data)` | `self` | Add a `.pyd` file from bytes. Chainable |
| `add_file(path, module_name=None)` | `self` | Add a `.pyd` file from disk path. Chainable |
| `load()` | `types.ModuleType` | Load the whole package in correct order |
| `get(submodule)` | `ModuleType \| None` | Get a loaded submodule by short name (`"parser"`) |
| `list_attrs()` | `dict` | Package-level attributes (from `__init__`) |
| `list_functions()` | `dict` | Functions exposed by the package |
| `list_classes()` | `dict` | Classes exposed by the package |
| `list_constants()` | `dict` | Constants exposed by the package |
| `list_imports()` | `dict` | Modules visible in package namespace |
| `list_submodules()` | `dict` | Full inspection of each submodule separately |
| `print_info()` | `None` | Full structured report (delegates to `PydMemoryLoader.print_info`) |
| `print_package_summary()` | `None` | Brief summary: file sizes and attribute lists per submodule |
| `print_submodule_info(name)` | `None` | Detailed report for one submodule |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `package` | `ModuleType \| None` | The loaded package module |
| `submodules` | `dict[str, ModuleType]` | All loaded submodules `{full_name: module}` |

---

### `ImportEvent`

Passed to the `callback` in `enable_import_tracking()`.

```python
event.name       # str  — full module name, e.g. "os.path"
event.cached     # bool — True if already in sys.modules (cache hit)
                 #        False if loading for the first time (new load)
event.caller     # str  — "filename.py:42 in my_function()"
event.callstack  # list[str] — full call stack
event.path       # list | None — search path used
```

---

## Inspection Examples

### Single module

```python
loader = PydMemoryLoader.from_file("parser.cp312-win_amd64.pyd")
mod = loader.load()

loader.print_info()
# ══════════════════════════════════════════════════════════════
#   Модуль  : parser
#   Тип     : <class 'module'>
#   Размер  : 139,264 байт
#
#   ┌─ Функции (1) ────────────────────────────────────────
#   │  parse_pattern(pattern)  # Parse a byte pattern string
#   └──────────────────────────────────────────────────────
#
#   ┌─ Классы (3) ────────────────────────────────────────
#   │  class Atom():
#   │      type  [class]
#   │      value [constant]
#   │  class AtomType(Enum):
#   │  ...

import pprint
pprint.pprint(loader.list_functions())
# {'parse_pattern': {'doc': 'Parse a byte pattern string',
#                    'signature': '(pattern)',
#                    'type': 'builtin_function_or_method'}}

pprint.pprint(loader.list_classes())
# {'Atom':     {'bases': ['object'], 'members': {'type': 'class', 'value': 'constant'}, ...},
#  'AtomType': {'bases': ['Enum'],   'members': {...}, ...}}
```

### DLL-level inspection

```python
loader.print_dll_exports()
# Экспорты DLL (2):
#   Python init:
#     PyInit_parser
#   Прочие:
#     ...

loader.print_dll_imports()
# Импорты DLL (3 библиотек, 47 функций):
#
#   Системные / Python:
#     python312.dll  (38 функций)
#     vcruntime140.dll  (5 функций)
#
#   Сторонние зависимости:
#     KERNEL32.dll  (4 функций):
#         GetLastError
#         ...
```

### Package inspection

```python
loader = PydPackageLoader.from_dir("atom", "./atom/")
pkg = loader.load()

loader.print_info()           # full report on the merged __init__ namespace
loader.print_package_summary()  # brief: file sizes + per-submodule attr lists
loader.print_submodule_info("reader")  # detailed report for atom.reader only

import pprint
pprint.pprint(loader.list_submodules())
# {'atom.parser': {'classes':   {'Atom': ..., 'AtomType': ...},
#                  'functions': {'parse_pattern': ...},
#                  'constants': {'PTR_SKIP': ...}},
#  'atom.reader': {'classes':   {'FastPeScanner': ..., 'PelitePattern': ...},
#                  'functions': {...},
#                  'constants': {...}}}
```

---

## Runtime Import Tracking

Track which modules get imported when your `.pyd` code runs — useful for finding hidden dependencies.

```python
loader = PydMemoryLoader.from_file("reader.cp312-win_amd64.pyd")
mod = loader.load()

# Simple: just print new imports as they happen
def on_import(event: ImportEvent):
    if not event.cached:
        print(f"[NEW]   {event.name:<40} ← {event.caller}")
    else:
        print(f"[cache] {event.name}")

loader.enable_import_tracking(callback=on_import)
mod.some_function()
loader.disable_import_tracking()

# Or inspect the full log afterwards
loader.print_import_log()                    # all events
loader.print_import_log(only_new=True)       # only first-time loads
loader.print_import_log(show_stack=True)     # with full call stack

# Raw access
for event in loader.import_log:
    if not event.cached:
        print(event.name, event.caller)
```

---

## How It Works

### Single `.pyd` loading

```
bytes
  └─► pythonmemorymodule.MemoryModule   — maps DLL into process memory
        └─► get_proc_addr("PyInit_foo") — locate init function
              └─► PyInit_foo()          — call it

              Returns either:
              ┌─ module object          → single-phase init (done)
              └─ moduledef*             → multi-phase init (PEP 451)
                    ├─ Py_mod_create(spec, def)  → creates module object
                    └─ Py_mod_exec(module)       → populates it
```

### Why `Py_IncRef` is called on everything

When Python shuts down, it calls `tp_dealloc` on all objects whose refcount drops to zero. For Cython types, `tp_dealloc` contains pointers into the `MemoryModule` memory region. If that memory is freed first (which it will be during GC), `tp_dealloc` causes a heap corruption crash (`0xC0000374`).

The fix: artificially increment refcounts on all C-extension objects so `tp_dealloc` is never called. This is an intentional memory leak that only affects process teardown.

### Package relative imports

```
PydPackageLoader.load():
  1. Register "atom" in sys.modules with __path__ = ["<memory>/atom"]
     and __spec__.submodule_search_locations set (required for relative imports)
  2. Load atom.parser → sys.modules["atom.parser"]
  3. Load atom.reader → sys.modules["atom.reader"]
  4. Install _MemoryPackageFinder in sys.meta_path
  5. Load atom.__init__ — when it runs `from .parser import X`:
       Python asks meta_path finders for "atom.parser"
       _MemoryPackageFinder sees it's already in sys.modules → returns it
  6. Remove _MemoryPackageFinder from sys.meta_path
  7. Copy __init__ attributes into the package module
```

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: attempted relative import with no known parent package` | Loading a submodule standalone that needs the package | Use `PydPackageLoader` instead of `PydMemoryLoader` |
| `RuntimeError: 'PyInit_foo' not found in DLL` | Wrong module name | Check exports with `loader.print_dll_exports()` or install `pefile` for auto-detection |
| `RuntimeError: MemoryModule: ...` | DLL failed to load | Check that all DLL dependencies are available (`loader.print_dll_imports()`) |
| `Py_mod_exec returned -1` | Module initialization failed | Usually a missing dependency — check `print_dll_imports()` |
| Crash on exit (`0xC0000374`) | tp_dealloc after memory freed | Should not happen with current version — file an issue |

---

## License

MIT
