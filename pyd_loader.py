"""
PydMemoryLoader — загрузка .pyd файлов в память без записи на диск.

Требования:
    pip install pythonmemorymodule
    pip install pefile  (опционально, для автоопределения имени модуля)

Использование:
    from pyd_loader import PydMemoryLoader

    loader = PydMemoryLoader.from_file("mymodule.cp312-win_amd64.pyd")
    mod = loader.load()

    loader.print_info()           # полный отчёт о модуле
    loader.list_functions()       # только функции
    loader.list_classes()         # только классы
    loader.print_dll_imports()    # что DLL импортирует на уровне PE

    loader.enable_import_tracking()
    mod.some_function()
    loader.print_import_log()
"""

from __future__ import annotations

import sys
import os
import ctypes
import time
import types
import inspect
import importlib.machinery
from typing import Optional, Any

if os.name != "nt":
    raise RuntimeError("PydMemoryLoader работает только на Windows (.pyd — это DLL)")

if sys.version_info < (3, 10):
    raise RuntimeError(
        f"pyd_loader требует Python 3.10+, "
        f"текущая версия: {sys.version_info.major}.{sys.version_info.minor}"
    )

import pythonmemorymodule

# ── Константы PyModuleDef ─────────────────────────────────────────────────────

class _PyModSlot:
    CREATE               = 1   # Py_mod_create
    EXEC                 = 2   # Py_mod_exec
    MULTIPLE_INTERPRETERS = 3  # Py_mod_multiple_interpreters (3.12+)
    GIL                  = 4   # Py_mod_gil                   (3.13+)
    ABI                  = 5   # Py_mod_abi                   (3.15+)
    NAME                 = 6   # Py_mod_name
    DOC                  = 7   # Py_mod_doc
    STATE_SIZE           = 8   # Py_mod_state_size
    METHODS              = 9   # Py_mod_methods
    STATE_TRAVERSE       = 10  # Py_mod_state_traverse
    STATE_CLEAR          = 11  # Py_mod_state_clear
    STATE_FREE           = 12  # Py_mod_state_free
    TOKEN                = 13  # Py_mod_token


# ── Структуры CPython (из moduleobject.h) ────────────────────────────────────
#
# PyObject_HEAD = ob_refcnt (Py_ssize_t, 8 bytes) + *ob_type (8 bytes) = 16 bytes
#
# PyModuleDef_Base:
#   PyObject_HEAD   16 bytes
#   m_init          8 bytes  (function pointer)
#   m_index         8 bytes  (Py_ssize_t)
#   m_copy          8 bytes  (PyObject*)
#   total           40 bytes
#
# PyModuleDef:
#   m_base          40 bytes
#   m_name          8 bytes  (char*)
#   m_doc           8 bytes  (char*)
#   m_size          8 bytes  (Py_ssize_t)
#   m_methods       8 bytes  (PyMethodDef*)
#   m_slots         8 bytes  (PyModuleDef_Slot*)   ← offset 72
#   m_traverse      8 bytes
#   m_clear         8 bytes
#   m_free          8 bytes
#
# PyModuleDef_Slot:
#   slot            4 bytes  (int) + 4 bytes padding = 8 bytes aligned
#   value           8 bytes  (void*)
#   total           16 bytes

class _PyObject_HEAD(ctypes.Structure):
    _fields_ = [
        ("ob_refcnt", ctypes.c_ssize_t),   # Py_ssize_t ob_refcnt
        ("ob_type",   ctypes.c_void_p),    # PyTypeObject *ob_type
    ]

class _PyModuleDef_Base(ctypes.Structure):
    _fields_ = [
        ("ob_base", _PyObject_HEAD),        # PyObject_HEAD (16 bytes)
        ("m_init",  ctypes.c_void_p),       # PyObject* (*m_init)(void)
        ("m_index", ctypes.c_ssize_t),      # Py_ssize_t m_index
        ("m_copy",  ctypes.c_void_p),       # PyObject* m_copy
    ]

class _PyModuleDef_Slot(ctypes.Structure):
    _fields_ = [
        ("slot",  ctypes.c_int),            # int slot  (4 bytes + 4 pad → 8 aligned)
        ("_pad",  ctypes.c_int),            # explicit padding
        ("value", ctypes.c_void_p),         # void *value
    ]

class _PyModuleDef(ctypes.Structure):
    _fields_ = [
        ("m_base",     _PyModuleDef_Base),                  # 40 bytes
        ("m_name",     ctypes.c_char_p),                    # const char*
        ("m_doc",      ctypes.c_char_p),                    # const char*
        ("m_size",     ctypes.c_ssize_t),                   # Py_ssize_t
        ("m_methods",  ctypes.c_void_p),                    # PyMethodDef*
        ("m_slots",    ctypes.POINTER(_PyModuleDef_Slot)),  # PyModuleDef_Slot*
        ("m_traverse", ctypes.c_void_p),                    # traverseproc
        ("m_clear",    ctypes.c_void_p),                    # inquiry
        ("m_free",     ctypes.c_void_p),                    # freefunc
    ]

# ── PE-уровень (определение имени модуля) ─────────────────────────────────────

def _detect_module_name_from_exports(data: bytes) -> Optional[str]:
    """Ищет PyInit_* в таблице экспортов DLL."""
    try:
        import pefile
        pe = pefile.PE(data=data)
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return None
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and exp.name.startswith(b"PyInit_"):
                return exp.name[7:].decode("utf-8", errors="replace")
    except Exception:
        pass
    return None

def _get_dll_exports(data: bytes) -> list[str]:
    """Все экспортируемые имена DLL."""
    try:
        import pefile
        pe = pefile.PE(data=data)
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return []
        return [
            exp.name.decode("utf-8", errors="replace")
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols
            if exp.name
        ]
    except Exception:
        return []
        
def _get_dll_imports(data: bytes) -> dict[str, list[str]]:
    """Таблица импортов DLL: {dll_name: [func, ...]}."""
    try:
        import pefile
        pe = pefile.PE(data=data)
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return {}
        result = {}
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("utf-8", errors="replace"))
                else:
                    funcs.append(f"ordinal#{imp.ordinal}")
            result[dll] = funcs
        return result
    except Exception:
        return {}

# ── CPython internals ─────────────────────────────────────────────────────────
# ── Работа со слотами PyModuleDef ─────────────────────────────────────────────

def _read_moduledef_slots(moduledef_obj) -> tuple[Optional[int], list[int]]:
    """
    Читает слоты из PyModuleDef через ctypes-структуры.

    id(obj) == адрес PyObject в памяти CPython — стандартная гарантия.
    Приводим адрес к _PyModuleDef* и читаем m_slots напрямую.
    """
    moduledef = _PyModuleDef.from_address(id(moduledef_obj))

    if not moduledef.m_slots:
        return None, []

    create_fn: Optional[int] = None
    exec_fns:  list[int]     = []

    idx = 0
    while True:
        slot = moduledef.m_slots[idx]
        if slot.slot == 0:
            break
        if slot.slot == _PyModSlot.CREATE:
            create_fn = slot.value
        elif slot.slot == _PyModSlot.EXEC:
            exec_fns.append(slot.value)
        idx += 1

    return create_fn, exec_fns


def _incref_all_c_objects(mod) -> None:
    """Рекурсивный Py_IncRef для предотвращения преждевременного tp_dealloc."""
    api = ctypes.pythonapi
    api.Py_IncRef.argtypes = [ctypes.py_object]
    api.Py_IncRef.restype  = None
    seen: set[int] = set()

    def _incref(obj):
        oid = id(obj)
        if oid in seen:
            return
        seen.add(oid)
        try:
            api.Py_IncRef(obj)
            if isinstance(obj, type):
                for v in vars(obj).values():
                    _incref(v)
                _incref(type(obj))
        except Exception:
            pass

    _incref(mod)
    for attr_name in dir(mod):
        try:
            _incref(getattr(mod, attr_name))
        except Exception:
            pass


# ── Классификация атрибутов ───────────────────────────────────

def _classify_attr(obj: Any) -> str:
    if inspect.isbuiltin(obj):
        return "builtin_function"
    if inspect.isfunction(obj):
        return "function"
    if inspect.ismethod(obj):
        return "method"
    if isinstance(obj, type):
        return "exception" if issubclass(obj, BaseException) else "class"
    if isinstance(obj, types.ModuleType):
        return "module"
    t = type(obj).__name__.lower()
    if "cyfunction" in t or "cython_function" in t:
        return "cyfunction"
    if type(obj).__name__ in ("int", "float", "str", "bool", "bytes", "NoneType"):
        return "constant"
    return type(obj).__name__



# ── Import tracker ────────────────────────────────────────────────────────────

class ImportEvent:
    """
    Событие импорта, передаваемое в callback.

    Атрибуты:
        name      — полное имя импортируемого модуля (str)
        cached    — True если модуль уже есть в sys.modules (из кэша)
        caller    — строка "файл:строка in функция()" — непосредственный вызыватель
        callstack — список строк стека вызовов (от верхнего к нижнему)
        path      — путь поиска (обычно None для top-level модулей)
    """
    __slots__ = ("name", "cached", "caller", "callstack", "path")

    def __init__(self, name: str, cached: bool, caller: str,
                 callstack: list, path):
        self.name      = name
        self.cached    = cached
        self.caller    = caller
        self.callstack = callstack
        self.path      = path

    def __repr__(self) -> str:
        flag = "кэш" if self.cached else "НОВЫЙ"
        return f"<ImportEvent [{flag}] {self.name!r} ← {self.caller}>"


class _ImportTracker:
    """Перехватчик import-вызовов через sys.meta_path."""

    def __init__(self):
        self.log: list[ImportEvent] = []
        self._active   = False
        self._callback = None   # callable(ImportEvent) | None

    def set_callback(self, fn):
        """Устанавливает callback. fn(event: ImportEvent) → None."""
        self._callback = fn

    def enable(self):
        if self not in sys.meta_path:
            sys.meta_path.insert(0, self)
        self._active = True

    def disable(self):
        if self in sys.meta_path:
            sys.meta_path.remove(self)
        self._active = False

    def find_module(self, fullname, path=None):
        return None

    def find_spec(self, fullname, path, target=None):
        if not self._active:
            return None

        frames = []
        try:
            frame = sys._getframe(1)
            while frame and len(frames) < 8:
                frames.append(
                    f"{os.path.basename(frame.f_code.co_filename)}"
                    f":{frame.f_lineno} in {frame.f_code.co_name}()"
                )
                frame = frame.f_back
        except Exception:
            pass

        event = ImportEvent(
            name      = fullname,
            cached    = fullname in sys.modules,
            caller    = frames[1] if len(frames) > 1 else "?",
            callstack = frames,
            path      = path,
        )
        self.log.append(event)

        if self._callback is not None:
            try:
                self._callback(event)
            except Exception as e:
                print(f"[ImportTracker] callback error: {e}")

        return None  # не перехватываем, только логируем


# ── Основной класс ────────────────────────────────────────────────────────────

class PydMemoryLoader:
    """
    Загружает .pyd (Cython/C-extension) DLL из байт в память без записи на диск.

    Инспекция модуля (доступна после load()):
        print_info()          — полный структурированный отчёт
        list_attrs()          — все атрибуты с категориями
        list_functions()      — функции с сигнатурами
        list_classes()        — классы с методами
        list_constants()      — константы и переменные
        list_imports()        — модули в namespace

    Инспекция DLL (доступна сразу, требует pefile):
        print_dll_exports()   — таблица экспортов PE
        print_dll_imports()   — таблица импортов PE (зависимости DLL)

    Отслеживание загрузки зависимостей в рантайме:
        enable_import_tracking()   — включить перехват import
        disable_import_tracking()  — выключить
        print_import_log()         — показать что было импортировано
        clear_import_log()         — очистить лог
        import_log                 — сырой список событий
    """

    def __init__(
        self,
        data: bytes,
        module_name: Optional[str] = None,
        register_in_sys_modules: bool = True,
        verbose: bool = False,
        suppress_debug: bool = True,
    ):
        """
        Args:
            data:                    Байты .pyd файла.
            module_name:             Имя модуля. None → определяется из экспортов DLL.
            register_in_sys_modules: Добавить в sys.modules после load().
            verbose:                 Выводить отладочные сообщения загрузчика.
            suppress_debug:          Подавлять DEBUG-вывод pythonmemorymodule (по умолчанию True).
                                     Вывод идёт через C printf напрямую в stdout,
                                     поэтому подавляется через os.dup2 на уровне OS.
        """
        if data[:2] != b"MZ":
            raise ValueError("Данные не являются PE/DLL (нет MZ сигнатуры)")

        self._data     = data
        self._verbose  = verbose
        self._register = register_in_sys_modules

        if module_name:
            self._module_name = module_name
        else:
            detected = _detect_module_name_from_exports(data)
            if not detected:
                raise ValueError(
                    "Не удалось определить имя модуля из экспортов. "
                    "Передай module_name= явно или установи pefile."
                )
            self._module_name = detected
            self._log(f"Имя модуля из экспортов: '{self._module_name}'")

        self._suppress_debug = suppress_debug
        self._mem_mod:   Optional[object]           = None
        self._module:    Optional[types.ModuleType] = None
        self._keepalive: list                       = []
        self._tracker    = _ImportTracker()

    # ── Фабричные методы ─────────────────────────────────────────────────────

    @classmethod
    def from_file(
        cls,
        path: str,
        module_name: Optional[str] = None,
        suppress_debug: bool = True,
        **kwargs,
    ) -> "PydMemoryLoader":
        """Создаёт загрузчик из файла на диске."""
        with open(path, "rb") as f:
            data = f.read()
        if module_name is None:
            basename = os.path.basename(path)
            module_name = basename.split(".")[0] or None
        return cls(data, module_name=module_name, suppress_debug=suppress_debug, **kwargs)

    def load(self) -> types.ModuleType:
        """
        Загружает .pyd и возвращает модуль.
        Повторный вызов возвращает кэшированный результат.
        """
        if self._module is not None:
            return self._module

        self._log(f"Загружаем '{self._module_name}' ({len(self._data):,} байт)...")

        base_name    = self._module_name.split(".")[-1]
        is_init      = base_name == "__init__"
        package_name = (
            self._module_name.replace(".__init__", "") if is_init
            else self._module_name.rpartition(".")[0]
        )
        register_name = package_name if is_init else self._module_name

        if package_name and package_name not in sys.modules:
            stub = types.ModuleType(package_name)
            stub.__package__ = package_name
            stub.__path__    = []
            sys.modules[package_name] = stub
            self._log(f"Создан stub-пакет: '{package_name}'")

        # Загружаем DLL в память
        try:
            # pythonmemorymodule имеет модульную переменную debug_output
            # которая перекрывает параметр debug= конструктора.
            # Временно выставляем её в False если нужно подавить вывод.
            orig_debug = getattr(pythonmemorymodule, "debug_output", None)
            if self._suppress_debug:
                pythonmemorymodule.debug_output = False
            try:
                self._mem_mod = pythonmemorymodule.MemoryModule(
                    data=self._data,
                    debug=not self._suppress_debug,
                )
            finally:
                if orig_debug is not None:
                    pythonmemorymodule.debug_output = orig_debug
            self._keepalive.append(self._mem_mod)
        except Exception as e:
            raise RuntimeError(f"MemoryModule загрузка провалилась: {e}") from e

        init_func = self._get_init_func(base_name)

        try:
            raw = init_func()
            time.sleep(0.01)  # небольшой запас на возможные race в C-расширениях
        except Exception as e:
            raise RuntimeError(f"PyInit_{base_name}() → {e}") from e

        if raw is None:
            raise RuntimeError(f"PyInit_{base_name}() вернул NULL")

        if type(raw).__name__ == "moduledef":
            self._log("Многофазная инициализация (PEP 451 / PyModuleDef slots)")
            module = self._init_multiphase(raw, register_name)
        else:
            self._log("Однофазная инициализация (классический PyModule_Create)")
            module = raw

        module.__package__ = package_name
        _incref_all_c_objects(module)

        if self._register:
            sys.modules[register_name] = module
            self._log(f"Зарегистрирован в sys.modules: '{register_name}'")

        self._module = module
        self._log("Загрузка завершена успешно.")
        return module

    @property
    def module(self) -> Optional[types.ModuleType]:
        """Загруженный модуль или None."""
        return self._module

    def __repr__(self) -> str:
        status = "загружен" if self._module else "не загружен"
        return f"<PydMemoryLoader '{self._module_name}' [{status}]>"

    # ── Инспекция модуля ─────────────────────────────────────────────────────

    def list_attrs(self) -> dict[str, dict]:
        """
        Все публичные атрибуты модуля.

        Возвращает: { имя: {"type": str, "category": str, "value": repr} }
        """
        self._require_loaded()
        result = {}
        for name in sorted(dir(self._module)):
            if name.startswith("__"):
                continue
            try:
                obj = getattr(self._module, name)
                result[name] = {
                    "type":     type(obj).__name__,
                    "category": _classify_attr(obj),
                    "value":    repr(obj)[:120],
                }
            except Exception as e:
                result[name] = {"type": "?", "category": "error", "value": str(e)}
        return result

    def list_functions(self) -> dict[str, dict]:
        """
        Функции и методы модуля.

        Возвращает: { имя: {"signature": str, "doc": str, "type": str} }
        """
        self._require_loaded()
        fn_cats = {"function", "builtin_function", "cyfunction", "method"}
        result = {}
        for name, info in self.list_attrs().items():
            if info["category"] not in fn_cats:
                continue
            obj = getattr(self._module, name, None)
            sig = doc = ""
            try:
                sig = str(inspect.signature(obj))
            except Exception:
                raw_doc = getattr(obj, "__doc__", "") or ""
                first = raw_doc.strip().splitlines()[0] if raw_doc.strip() else ""
                sig = first if "(" in first else ""
            try:
                doc = (getattr(obj, "__doc__", "") or "").strip().splitlines()[0]
            except Exception:
                pass
            result[name] = {"type": info["type"], "signature": sig, "doc": doc}
        return result

    def list_classes(self) -> dict[str, dict]:
        """
        Классы модуля с их членами.

        Возвращает: { класс: {"bases": [...], "doc": str, "members": {имя: категория}} }
        """
        self._require_loaded()
        result = {}
        for name, info in self.list_attrs().items():
            if info["category"] not in ("class", "exception"):
                continue
            obj = getattr(self._module, name, None)
            if not isinstance(obj, type):
                continue
            members = {}
            for mname in sorted(dir(obj)):
                if mname.startswith("_"):
                    continue
                try:
                    members[mname] = _classify_attr(getattr(obj, mname))
                except Exception:
                    members[mname] = "?"
            doc_raw = getattr(obj, "__doc__", "") or ""
            doc = doc_raw.strip().splitlines()[0] if doc_raw.strip() else ""
            result[name] = {
                "category": info["category"],
                "bases":    [b.__name__ for b in obj.__bases__],
                "doc":      doc,
                "members":  members,
            }
        return result

    def list_constants(self) -> dict[str, Any]:
        """Константы и переменные модуля (не функции, не классы, не модули)."""
        self._require_loaded()
        skip = {"function", "builtin_function", "cyfunction", "method",
                "class", "exception", "module"}
        result = {}
        for name, info in self.list_attrs().items():
            if info["category"] not in skip:
                try:
                    result[name] = getattr(self._module, name)
                except Exception:
                    result[name] = None
        return result

    def list_imports(self) -> dict[str, str]:
        """
        Модули, видимые в namespace загруженного модуля
        (т.е. импортированные внутри него).

        Возвращает: { имя_атрибута: полное_имя_модуля }
        """
        self._require_loaded()
        return {
            name: getattr(obj, "__name__", name)
            for name, info in self.list_attrs().items()
            if info["category"] == "module"
            for obj in [getattr(self._module, name, None)]
            if isinstance(obj, types.ModuleType)
        }

    def print_info(self) -> None:
        """Выводит полный структурированный отчёт о модуле."""
        self._require_loaded()
        mod = self._module
        sep = "=" * 62

        print(f"\n{sep}")
        print(f"  Модуль  : {self._module_name}")
        print(f"  Тип     : {type(mod)}")
        print(f"  Размер  : {len(self._data):,} байт")
        doc = (getattr(mod, "__doc__", "") or "").strip()
        if doc:
            print(f"  Докстр  : {doc[:80]}")
        print(sep)

        # ── Функции
        funcs = self.list_functions()
        if funcs:
            print(f"\n  ┌─ Функции ({len(funcs)}) {'─'*40}")
            for name, info in sorted(funcs.items()):
                sig  = info["signature"] or ""
                note = f"  # {info['doc']}" if info["doc"] else ""
                print(f"  │  {name}{sig}{note}")
            print(f"  └{'─'*50}")

        # ── Классы
        classes = self.list_classes()
        if classes:
            print(f"\n  ┌─ Классы ({len(classes)}) {'─'*40}")
            for cname, ci in sorted(classes.items()):
                bases = f"({', '.join(ci['bases'])})" if ci["bases"] else ""
                doc   = f"  # {ci['doc']}" if ci["doc"] else ""
                print(f"  │  class {cname}{bases}:{doc}")
                for mname, mcat in sorted(ci["members"].items()):
                    print(f"  │      {mname}  [{mcat}]")
            print(f"  └{'─'*50}")

        # ── Константы
        consts = self.list_constants()
        if consts:
            print(f"\n  ┌─ Константы ({len(consts)}) {'─'*38}")
            for name, val in sorted(consts.items()):
                print(f"  │  {name} = {repr(val)[:70]}")
            print(f"  └{'─'*50}")

        # ── Импорты в namespace
        imports = self.list_imports()
        if imports:
            print(f"\n  ┌─ Импорты в namespace ({len(imports)}) {'─'*30}")
            for attr, full in sorted(imports.items()):
                marker = "[внешний]" if attr != full.split(".")[-1] else ""
                print(f"  │  {attr} → {full}  {marker}")
            print(f"  └{'─'*50}")

        print(f"\n{sep}\n")

    def print_dll_exports(self) -> None:
        """Таблица экспортов DLL (требует pefile)."""
        exports = _get_dll_exports(self._data)
        if not exports:
            print("Экспорты не найдены (установи pefile: pip install pefile)")
            return
        pyinit  = [e for e in exports if e.startswith("PyInit_")]
        other   = [e for e in exports if not e.startswith("PyInit_")]
        print(f"\nЭкспорты DLL ({len(exports)}):")
        if pyinit:
            print("  Python init:")
            for e in pyinit:
                print(f"    {e}")
        if other:
            print("  Прочие:")
            for e in sorted(other):
                print(f"    {e}")

    def print_dll_imports(self) -> None:
        """
        Таблица импортов DLL — какие DLL и функции нужны модулю на уровне PE.
        Позволяет понять зависимости без запуска кода (требует pefile).
        """
        imports = _get_dll_imports(self._data)
        if not imports:
            print("Импорты не найдены (установи pefile: pip install pefile)")
            return

        # Группируем: Python/CRT отдельно от прочих
        python_dlls = {k: v for k, v in imports.items()
                       if "python" in k.lower() or "vcruntime" in k.lower()
                       or "api-ms" in k.lower() or "kernel32" in k.lower()
                       or "ucrtbase" in k.lower()}
        other_dlls  = {k: v for k, v in imports.items() if k not in python_dlls}

        print(f"\nИмпорты DLL ({len(imports)} библиотек, "
              f"{sum(len(v) for v in imports.values())} функций):")

        if python_dlls:
            print("\n  Системные / Python:")
            for dll, funcs in sorted(python_dlls.items()):
                print(f"    {dll}  ({len(funcs)} функций)")

        if other_dlls:
            print("\n  Сторонние зависимости:")
            for dll, funcs in sorted(other_dlls.items()):
                print(f"    {dll}  ({len(funcs)} функций):")
                for f in sorted(funcs):
                    print(f"        {f}")

    # ── Import tracker ────────────────────────────────────────────────────────

    def enable_import_tracking(self, callback=None) -> None:
        """
        Включает перехват всех вызовов import через sys.meta_path.

        Args:
            callback: необязательная функция вида callback(event: ImportEvent).
                      Вызывается синхронно при каждом import.
                      event.cached — True если модуль уже в sys.modules (из кэша),
                                     False если загружается впервые (новый).

        Пример:
            def on_import(event):
                if not event.cached:
                    print(f"Новый модуль: {event.name}  ← {event.caller}")

            loader.enable_import_tracking(callback=on_import)
        """
        if callback is not None:
            self._tracker.set_callback(callback)
        self._tracker.enable()
        cb_status = f", callback={callback.__name__}" if callback else ""
        print(f"[ImportTracker] Включён{cb_status}. Вызови print_import_log() для просмотра.")

    def disable_import_tracking(self) -> None:
        """Выключает перехват импортов."""
        self._tracker.disable()
        print(f"[ImportTracker] Выключен. Поймано событий: {len(self._tracker.log)}")

    def clear_import_log(self) -> None:
        """Очищает лог перехваченных импортов."""
        self._tracker.log.clear()

    @property
    def import_log(self) -> list[dict]:
        """Сырой список событий импорта."""
        return self._tracker.log

    def print_import_log(self, show_stack: bool = False, only_new: bool = False) -> None:
        """
        Выводит лог перехваченных import-вызовов.

        Args:
            show_stack: показывать полный стек вызовов для каждого события.
            only_new:   показывать только новые загрузки (не из кэша sys.modules).
        """
        log = self._tracker.log
        if only_new:
            log = [e for e in log if not e.cached]

        if not log:
            print("Лог пуст. Включи enable_import_tracking() перед вызовом кода.")
            return

        # Группируем по имени для статистики
        from collections import Counter
        counts = Counter(e.name for e in log)

        print(f"\nЛог импортов ({len(log)} событий, "
              f"{len(counts)} уникальных модулей):\n")

        sep = "─" * 55
        for i, entry in enumerate(log, 1):
            status = "кэш" if entry.cached else "НОВЫЙ"
            count_str = f" ×{counts[entry.name]}" if counts[entry.name] > 1 else ""
            print(f"  {i:3}. [{status}]{count_str}  {entry.name}")
            print(f"       ← {entry.caller}")
            if show_stack:
                for frame in entry.callstack[2:]:
                    print(f"          {frame}")
            print()

        # Итог: новые загрузки
        new = [e for e in log if not e.cached]
        if new:
            print(f"  Новых загрузок: {len(new)}")
            for e in new:
                print(f"    + {e.name}")
        print()

    # ── Внутренние вспомогательные методы ─────────────────────────────────────

    def _require_loaded(self) -> None:
        if self._module is None:
            raise RuntimeError("Модуль ещё не загружен — вызови .load()")

    def _log(self, msg: str) -> None:
        if self._verbose:
            print(f"[PydMemoryLoader] {msg}")

    def _get_init_func(self, base_name: str):
        init_name = f"PyInit_{base_name}"
        try:
            addr = self._mem_mod.get_proc_addr(init_name)
        except Exception as e:
            raise RuntimeError(f"Символ '{init_name}' не найден в DLL: {e}") from e

        FuncType = ctypes.PYFUNCTYPE(ctypes.py_object)
        if isinstance(addr, int):
            fn = FuncType(addr)
        elif callable(addr):
            fn = ctypes.cast(addr, FuncType)
        else:
            raise RuntimeError(f"get_proc_addr вернул неожиданный тип: {type(addr)}")

        self._keepalive.extend([FuncType, fn])
        return fn

    def _init_multiphase(self, moduledef, register_name: str) -> types.ModuleType:
        self._keepalive.append(moduledef)
        create_fn, exec_fns = _read_moduledef_slots(moduledef)
        self._log(f"Слоты: create={'да' if create_fn else 'нет'}, exec={len(exec_fns)}")

        # spec.parent вычисляется автоматически из name:
        #   "atom.parser" → parent = "atom"
        #   "atom"        → parent = ""
        # submodule_search_locations != None сигнализирует CPython что это пакет
        # и разрешает relative imports внутри него.

        # Является ли этот модуль пакетом?
        existing = sys.modules.get(register_name)
        is_package = (
            # Явно зарегистрирован как пакет
            getattr(existing, "__path__", None) is not None
            # Или это top-level имя без точки (atom, не atom.parser)
            or "." not in register_name
        )

        spec = importlib.machinery.ModuleSpec(
            register_name,
            loader=None,
            origin=f"<memory>/{register_name}",
            is_package=is_package,
        )

        # Если пакет уже в sys.modules с настроенным __path__ — берём его
        if existing is not None:
            p = getattr(existing, "__path__", None)
            if p is not None:
                spec.submodule_search_locations = list(p)

        self._keepalive.append(spec)

        # 1. Выполняем Py_mod_create если есть
        if create_fn:
            CreateFT = ctypes.PYFUNCTYPE(ctypes.py_object, ctypes.py_object, ctypes.py_object)
            create_func = CreateFT(create_fn)
            self._keepalive.extend([CreateFT, create_func])
            module = create_func(spec, moduledef)
            if module is None:
                raise RuntimeError("Py_mod_create вернул NULL")
            self._log("Py_mod_create выполнен → получен модуль")
        else:
            # fallback — просто пустой модуль
            module = types.ModuleType(register_name)
            self._log("Py_mod_create отсутствует → fallback types.ModuleType")

        # 2. Выполняем ВСЕ Py_mod_exec слоты (если они есть)
        ExecFT = ctypes.PYFUNCTYPE(ctypes.c_int, ctypes.py_object)
        self._keepalive.append(ExecFT)
        for i, fn_addr in enumerate(exec_fns):
            exec_func = ExecFT(fn_addr)
            self._keepalive.append(exec_func)
            rc = exec_func(module)
            if rc != 0:
                raise RuntimeError(f"Py_mod_exec[{i}] вернул ошибку {rc} (addr={hex(fn_addr)})")
            self._log(f"Py_mod_exec[{i}] выполнен успешно")

        # Больше ничего не делаем — если модуль не имеет exec-слотов, то он уже готов

        try:
            module.__pyd_keepalive__ = self._keepalive  # защита от GC
        except Exception:
            pass

        return module


# ── PydPackageLoader  ──────────────────────

class PydPackageLoader:
    """
    Загружает пакет состоящий из нескольких .pyd файлов без записи на диск.

    Порядок загрузки:
      1. Регистрирует пакет в sys.modules с правильным __path__ (виртуальным)
      2. Загружает submodule-файлы (parser, reader, ...) через PydMemoryLoader
      3. Загружает __init__.pyd последним — к этому моменту relative imports работают

    Пример:
        loader = PydPackageLoader("atom")
        loader.add("__init__.cp312-win_amd64.pyd",  data=init_bytes)
        loader.add("parser.cp312-win_amd64.pyd",    data=parser_bytes)
        loader.add("reader.cp312-win_amd64.pyd",    data=reader_bytes)
        pkg = loader.load()

        # Или из директории
        loader = PydPackageLoader.from_dir("atom", "./atom_pyd/")
        pkg = loader.load()

        import atom
        atom.parse_pattern("...")
    """
    def __init__(
        self,
        package_name: str,
        suppress_debug: bool = True,
        verbose: bool = False,
    ):
        """
        Args:
            package_name:   Имя пакета верхнего уровня (например "atom").
            suppress_debug: Подавлять DEBUG-вывод pythonmemorymodule.
            verbose:        Выводить отладочные сообщения загрузчика.
        """
        self._package_name  = package_name
        self._suppress_debug = suppress_debug
        self._verbose        = verbose
        self._entries: list[tuple[str, bytes]] = []
        self._loaders: dict[str, PydMemoryLoader] = {}
        self._package_module: Optional[types.ModuleType] = None

    @classmethod
    def from_dir(cls, package_name: str, directory: str, pattern: str = "*.pyd", **kwargs):
        """
        Создаёт загрузчик из директории с .pyd файлами.

        Args:
            package_name: Имя пакета.
            directory:    Путь к директории с .pyd файлами.
            pattern:      Glob-паттерн файлов (по умолчанию *.pyd).
        """
        import glob
        pkg = cls(package_name, **kwargs)
        files = sorted(glob.glob(os.path.join(directory, pattern)))
        if not files:
            raise FileNotFoundError(f"Нет .pyd файлов в {directory!r} по маске {pattern!r}")
        for path in files:
            with open(path, "rb") as f:
                data = f.read()
            basename = os.path.basename(path)
            mod_base = basename.split(".")[0]
            pkg.add(mod_base, data)
        return pkg

    def add(self, module_name: str, data: bytes) -> "PydPackageLoader":
        """
        Добавляет .pyd файл в пакет.

        Args:
            module_name: Короткое имя субмодуля: "__init__", "parser", "reader" и т.д.
                         Для __init__ автоматически обрабатывается как корень пакета.
            data:        Байты .pyd файла.

        Returns:
            self (для chaining)
        """
        self._entries.append((module_name, data))
        return self


    def add_file(self, path: str, module_name: Optional[str] = None) -> "PydPackageLoader":
        """Добавляет .pyd файл из пути на диске."""
        with open(path, "rb") as f:
            data = f.read()
        if module_name is None:
            module_name = os.path.basename(path).split(".")[0]
        return self.add(module_name, data)

    def load(self) -> types.ModuleType:
        """
        Загружает весь пакет в правильном порядке.
        Повторный вызов возвращает кэшированный результат.
        """
        if self._package_module is not None:
            return self._package_module

        pkg = self._package_name
        self._log(f"Загрузка пакета '{pkg}' ({len(self._entries)} файлов)...")

        # ── Шаг 1: регистрируем пакет с виртуальным __path__ ─────────────
        # __path__ должен быть непустым списком чтобы Python разрешал
        # относительные импорты. Используем виртуальный путь-маркер.
        if pkg not in sys.modules:
            pkg_mod = types.ModuleType(pkg)
            pkg_mod.__package__ = pkg
            pkg_mod.__path__    = [f"<memory>/{pkg}"]
            pkg_mod.__spec__    = importlib.machinery.ModuleSpec(
                pkg, loader=None, origin=f"<memory>/{pkg}/__init__"
            )
            pkg_mod.__spec__.submodule_search_locations = pkg_mod.__path__
            sys.modules[pkg] = pkg_mod
            self._log(f"Пакет '{pkg}' зарегистрирован")
        else:
            pkg_mod = sys.modules[pkg]
            # Убеждаемся что __path__ установлен
            if not getattr(pkg_mod, "__path__", None):
                pkg_mod.__path__ = [f"<memory>/{pkg}"]
            self._log(f"Пакет '{pkg}' уже существует")

        # ── Шаг 2: устанавливаем перехватчик для relative imports ────────
        # Когда __init__.pyd делает "from .parser import X", Python ищет
        # "atom.parser" через importlib. Регистрируем meta_path finder
        # который перенаправит этот поиск на наши загруженные модули.
        # ── Шаг 3: загружаем субмодули (всё кроме __init__) ────────────
        init_entry = None
        for mod_name, data in self._entries:
            if mod_name == "__init__":
                init_entry = (mod_name, data)
                continue
            full_name = f"{pkg}.{mod_name}"
            self._log(f"  → субмодуль {full_name}")
            loader = PydMemoryLoader(
                data,
                module_name=full_name,
                suppress_debug=self._suppress_debug,
                verbose=self._verbose,
            )
            sub_mod = loader.load()
            self._loaders[full_name] = loader
            setattr(pkg_mod, mod_name, sub_mod)

        # ── Шаг 4: загружаем __init__ последним ──────────────────────────
        # Finder устанавливается непосредственно перед exec-фазой __init__,
        # чтобы перехватывать relative imports именно во время их выполнения.
        if init_entry:
            self._log(f"  → __init__ пакета {pkg}")
            _, data = init_entry
            finder = _MemoryPackageFinder(pkg, self._loaders)
            sys.meta_path.insert(0, finder)
            try:
                init_loader = PydMemoryLoader(
                    data,
                    module_name=pkg,
                    suppress_debug=self._suppress_debug,
                    verbose=self._verbose,
                    register_in_sys_modules=False,
                )
                init_mod = init_loader.load()
                self._loaders[pkg] = init_loader
                # Переносим атрибуты из __init__ в пакет
                for k, v in vars(init_mod).items():
                    if not k.startswith("__") or k in ("__all__", "__version__"):
                        setattr(pkg_mod, k, v)
            finally:
                sys.meta_path.remove(finder)

        self._package_module = pkg_mod
        self._log(f"Пакет '{pkg}' полностью загружен")
        return pkg_mod

    @property
    def package(self) -> Optional[types.ModuleType]:
        """Загруженный пакет или None."""
        return self._package_module


    @property
    def submodules(self) -> dict[str, types.ModuleType]:
        """Словарь загруженных субмодулей {full_name: module}."""
        return {k: v.module for k, v in self._loaders.items() if v.module}

    def get(self, submodule: str) -> Optional[types.ModuleType]:
        """Возвращает загруженный субмодуль по короткому имени."""
        return self._loaders.get(f"{self._package_name}.{submodule}", 
               self._loaders.get(submodule, PydMemoryLoader.__new__(PydMemoryLoader))).module

    def print_package_summary(self) -> None:
        """Краткая сводка: файлы пакета и список атрибутов каждого субмодуля."""
        sep = "=" * 62
        print(f"\n{sep}")
        print(f"  Пакет: {self._package_name}")
        print(f"  Файлов: {len(self._entries)}")
        for name, data in self._entries:
            print(f"    {'__init__' if name == '__init__' else name:<20} {len(data):>8,} байт")
        print(sep)
        if self._package_module:
            for full_name, ldr in self._loaders.items():
                print(f"\n  [{full_name}]")
                if ldr.module:
                    attrs = [a for a in dir(ldr.module) if not a.startswith("__")]
                    print(f"    Атрибуты: {attrs}")
        print(f"\n{sep}\n")

    def print_info(self) -> None:
        """Полный структурированный отчёт о пакете: функции, классы, константы, импорты."""
        self._pkg_loader().print_info()

    # ── Делегирование методов инспекции к пакету ─────────────────────────────
    # Все list_*/print_* методы работают с объединённым namespace пакета
    # (т.е. тем что видно через import atom).

    def _pkg_loader(self) -> "PydMemoryLoader":
        """Возвращает временный PydMemoryLoader обёртку над пакетным модулем."""
        if not self._package_module:
            raise RuntimeError("Сначала вызови load()")
        # Создаём lightweight обёртку без загрузки — только для инспекции
        stub = PydMemoryLoader.__new__(PydMemoryLoader)
        stub._module      = self._package_module
        stub._data        = b""
        stub._verbose     = self._verbose
        stub._module_name = self._package_name
        return stub

    def list_attrs(self) -> dict:
        """Все публичные атрибуты пакета (объединённый namespace после __init__)."""
        return self._pkg_loader().list_attrs()

    def list_functions(self) -> dict:
        """Функции и методы доступные в пакете."""
        return self._pkg_loader().list_functions()

    def list_classes(self) -> dict:
        """Классы доступные в пакете."""
        return self._pkg_loader().list_classes()

    def list_constants(self) -> dict:
        """Константы и переменные пакета."""
        return self._pkg_loader().list_constants()

    def list_imports(self) -> dict:
        """Модули видимые в namespace пакета."""
        return self._pkg_loader().list_imports()

    def list_submodules(self) -> dict[str, dict]:
        """
        Инспекция каждого субмодуля отдельно.
        Возвращает { "atom.parser": {"functions": ..., "classes": ..., ...} }
        """
        result = {}
        for full_name, loader in self._loaders.items():
            if loader.module is None:
                continue
            result[full_name] = {
                "functions": loader.list_functions(),
                "classes":   loader.list_classes(),
                "constants": loader.list_constants(),
            }
        return result

    def print_submodule_info(self, submodule: str) -> None:
        """
        Печатает подробный отчёт по конкретному субмодулю.

        Args:
            submodule: короткое имя ("parser", "reader") или полное ("atom.parser")
        """
        full = submodule if "." in submodule else f"{self._package_name}.{submodule}"
        loader = self._loaders.get(full) or self._loaders.get(submodule)
        if loader is None:
            print(f"Субмодуль '{submodule}' не найден. Доступны: {list(self._loaders)}")
            return
        loader.print_info()

    def __repr__(self) -> str:
        status = "загружен" if self._package_module else "не загружен"
        return f"<PydPackageLoader '{self._package_name}' [{len(self._entries)} файлов, {status}]>"

    def _log(self, msg: str) -> None:
        if self._verbose:
            print(f"[PydPackage] {msg}")


class _MemoryPackageFinder:
    """
    sys.meta_path finder для перенаправления relative imports пакета
    на уже загруженные в памяти субмодули.

    Когда __init__.pyd делает "from .parser import X":
      → Python ищет "atom.parser" через meta_path
      → Этот finder видит что "atom.parser" уже в sys.modules
      → Возвращает spec указывающий на уже загруженный модуль
    """

    def __init__(self, package_name: str, loaders: dict):
        self._pkg = package_name
        self._loaders = loaders

    def find_spec(self, fullname, path, target=None):
        # Интересуют только субмодули нашего пакета
        if not fullname.startswith(self._pkg + "."):
            return None
        # Если уже загружен — возвращаем spec для него
        if fullname in sys.modules:
            mod = sys.modules[fullname]
            spec = importlib.machinery.ModuleSpec(
                fullname,
                loader=_AlreadyLoadedLoader(mod),
                origin=getattr(mod, "__file__", f"<memory>/{fullname}"),
            )
            return spec
        return None


class _AlreadyLoadedLoader:
    """Loader-заглушка для модулей уже загруженных в память."""
    def __init__(self, module):
        self._module = module

    def create_module(self, spec):
        return self._module

    def exec_module(self, module):
        pass  # уже выполнен
