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

try:
    import pythonmemorymodule
except ImportError as e:
    raise ImportError("Установи зависимость: pip install pythonmemorymodule") from e




# ── Константы PyModuleDef ─────────────────────────────────────────────────────

_Py_mod_create = 1
_Py_mod_exec   = 2
_OFF_M_SLOTS   = 72
_SLOT_SIZE     = 16  # sizeof(PyModuleDef_Slot)


# ── PE-уровень (через pefile) ─────────────────────────────────────────────────

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

def _read_moduledef_slots(moduledef_obj) -> tuple[Optional[int], list[int]]:
    base = id(moduledef_obj)
    slots_addr = ctypes.c_uint64.from_address(base + _OFF_M_SLOTS).value
    if slots_addr == 0:
        return None, []
    create_fn = None
    exec_fns: list[int] = []
    idx = 0
    while True:
        s_type = ctypes.c_int32.from_address(slots_addr + idx * _SLOT_SIZE).value
        s_val  = ctypes.c_uint64.from_address(slots_addr + idx * _SLOT_SIZE + 8).value
        if s_type == 0:
            break
        if s_type == _Py_mod_create:
            create_fn = s_val
        elif s_type == _Py_mod_exec:
            exec_fns.append(s_val)
        idx += 1
    return create_fn, exec_fns


def _find_python_dll_proc(name: bytes) -> Optional[int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.restype  = ctypes.c_void_p
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetProcAddress.restype    = ctypes.c_void_p
    kernel32.GetProcAddress.argtypes   = [ctypes.c_void_p, ctypes.c_char_p]
    py_ver = f"{sys.version_info.major}{sys.version_info.minor}"
    hmod = kernel32.GetModuleHandleW(f"python{py_ver}.dll")
    if not hmod:
        return None
    return kernel32.GetProcAddress(hmod, name) or None


def _incref_all_c_objects(mod) -> None:
    """Рекурсивный Py_IncRef — предотвращает краш tp_dealloc при финализации."""
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


# ── Классификация атрибутов ───────────────────────────────────────────────────

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
                    "Не удалось определить имя модуля из экспортов DLL. "
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

    # ── Загрузка ─────────────────────────────────────────────────────────────

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
            self._log(f"Заглушка пакета: '{package_name}'")

        try:
            # pythonmemorymodule имеет модульную переменную debug_output
            # которая перекрывает параметр debug= конструктора.
            # Временно выставляем её в False если нужно подавить вывод.
            _orig_flag = getattr(pythonmemorymodule, "debug_output", None)
            if self._suppress_debug:
                pythonmemorymodule.debug_output = False
            try:
                self._mem_mod = pythonmemorymodule.MemoryModule(
                    data=self._data,
                    debug=not self._suppress_debug,
                )
            finally:
                if _orig_flag is not None:
                    pythonmemorymodule.debug_output = _orig_flag
            self._keepalive.append(self._mem_mod)
        except Exception as e:
            raise RuntimeError(f"MemoryModule: {e}") from e

        init_func = self._get_init_func(base_name)

        try:
            raw = init_func()
            time.sleep(0.02)
        except Exception as e:
            raise RuntimeError(f"PyInit_{base_name}(): {e}") from e
        if raw is None:
            raise RuntimeError(f"PyInit_{base_name}() вернул NULL")

        if type(raw).__name__ == "moduledef":
            self._log("Многофазная инициализация (PEP 451)...")
            module = self._init_multiphase(raw, register_name)
        else:
            self._log("Однофазная инициализация.")
            module = raw

        module.__package__ = package_name
        _incref_all_c_objects(module)

        if self._register:
            sys.modules[register_name] = module
            self._log(f"sys.modules['{register_name}'] = OK")

        self._module = module
        self._log("Загрузка завершена.")
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
            except (ValueError, TypeError):
                raw_doc = getattr(obj, "__doc__", "") or ""
                first = raw_doc.strip().splitlines()[0] if raw_doc.strip() else ""
                sig = first if "(" in first else ""
            try:
                lines = (getattr(obj, "__doc__", "") or "").strip().splitlines()
                doc = lines[0] if lines else ""
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

    # ── Внутренние методы ─────────────────────────────────────────────────────

    def _require_loaded(self) -> None:
        if self._module is None:
            raise RuntimeError("Сначала вызови load()")

    def _log(self, msg: str) -> None:
        if self._verbose:
            print(f"[PydLoader] {msg}")

    def _get_init_func(self, base_name: str):
        init_name = f"PyInit_{base_name}"
        try:
            addr = self._mem_mod.get_proc_addr(init_name)
        except Exception as e:
            raise RuntimeError(
                f"'{init_name}' не найдена в DLL — проверь имя модуля. {e}"
            ) from e

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

        addr_exec = _find_python_dll_proc(b"PyModule_ExecDef")

        # spec.parent вычисляется автоматически из name:
        #   "atom.parser" → parent = "atom"
        #   "atom"        → parent = ""
        # submodule_search_locations != None сигнализирует CPython что это пакет
        # и разрешает relative imports внутри него.

        # Является ли этот модуль пакетом?
        existing    = sys.modules.get(register_name)
        is_package  = (
            # Явно зарегистрирован как пакет
            getattr(existing, "__path__", None) is not None
            # Или это top-level имя без точки (atom, не atom.parser)
            or "." not in register_name
        )

        spec = importlib.machinery.ModuleSpec(
            register_name,
            loader      = None,
            origin      = f"<memory>/{register_name}",
            is_package  = is_package,
        )

        # Если пакет уже в sys.modules с настроенным __path__ — берём его
        if existing is not None:
            existing_path = getattr(existing, "__path__", None)
            if existing_path is not None:
                spec.submodule_search_locations = list(existing_path)

        self._keepalive.append(spec)

        if create_fn:
            _FT = ctypes.PYFUNCTYPE(ctypes.py_object, ctypes.py_object, ctypes.py_object)
            _fn = _FT(create_fn)
            self._keepalive.extend([_FT, _fn])
            module = _fn(spec, moduledef)
            if module is None:
                raise RuntimeError("Py_mod_create вернул NULL")
            self._log(f"Py_mod_create OK → {type(module)}")
        else:
            addr_new = _find_python_dll_proc(b"PyModule_NewObject")
            if addr_new:
                _FT = ctypes.PYFUNCTYPE(ctypes.py_object, ctypes.py_object)
                _fn = _FT(addr_new)
                self._keepalive.extend([_FT, _fn])
                module = _fn(register_name)
                if module is None:
                    raise RuntimeError("PyModule_NewObject вернул NULL")
                self._log("PyModule_NewObject OK")
            else:
                module = types.ModuleType(register_name)
                self._log("Fallback types.ModuleType")

        _ExecFT = ctypes.PYFUNCTYPE(ctypes.c_int, ctypes.py_object)
        self._keepalive.append(_ExecFT)
        for i, fn_addr in enumerate(exec_fns):
            _efn = _ExecFT(fn_addr)
            self._keepalive.append(_efn)
            rc = _efn(module)
            if rc != 0:
                raise RuntimeError(f"Py_mod_exec[{i}] @ {hex(fn_addr)} вернул {rc}")
            self._log(f"Py_mod_exec[{i}] OK")

        if not exec_fns and addr_exec:
            _FT2 = ctypes.PYFUNCTYPE(ctypes.c_int, ctypes.py_object, ctypes.py_object)
            _fn2 = _FT2(addr_exec)
            self._keepalive.extend([_FT2, _fn2])
            rc = _fn2(module, moduledef)
            if rc != 0:
                raise RuntimeError(f"PyModule_ExecDef вернул {rc}")
            self._log("PyModule_ExecDef OK")

        try:
            module.__pyd_keepalive__ = self._keepalive
        except Exception:
            pass

        return module


# ── Загрузчик пакета из нескольких .pyd ──────────────────────────────────────

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

        # { submodule_name: bytes }  — в порядке добавления
        self._entries: list[tuple[str, bytes]] = []
        self._loaders: dict[str, PydMemoryLoader] = {}
        self._package_module: Optional[types.ModuleType] = None

    # ── Фабричные методы ─────────────────────────────────────────────────────

    @classmethod
    def from_dir(
        cls,
        package_name: str,
        directory: str,
        pattern: str = "*.pyd",
        **kwargs,
    ) -> "PydPackageLoader":
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
            raise FileNotFoundError(
                f"Не найдено .pyd файлов по паттерну {pattern!r} в {directory!r}"
            )
        for path in files:
            with open(path, "rb") as f:
                data = f.read()
            # Имя модуля из имени файла: "parser.cp312-win_amd64.pyd" → "parser"
            basename    = os.path.basename(path)
            module_base = basename.split(".")[0]  # "parser"
            pkg.add(module_base, data)
        return pkg

    # ── Публичный API ─────────────────────────────────────────────────────────

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
        self._log(f"Загружаем пакет '{pkg}' ({len(self._entries)} файлов)...")

        # ── Шаг 1: регистрируем пакет с виртуальным __path__ ─────────────
        # __path__ должен быть непустым списком чтобы Python разрешал
        # относительные импорты. Используем виртуальный путь-маркер.
        if pkg not in sys.modules:
            pkg_mod = types.ModuleType(pkg)
            pkg_mod.__package__ = pkg
            pkg_mod.__path__    = [f"<memory>/{pkg}"]  # виртуальный путь
            pkg_mod.__spec__    = importlib.machinery.ModuleSpec(
                pkg, loader=None, origin=f"<memory>/{pkg}/__init__"
            )
            pkg_mod.__spec__.submodule_search_locations = pkg_mod.__path__
            sys.modules[pkg] = pkg_mod
            self._log(f"Пакет '{pkg}' зарегистрирован в sys.modules")
        else:
            pkg_mod = sys.modules[pkg]
            # Убеждаемся что __path__ установлен
            if not getattr(pkg_mod, "__path__", None):
                pkg_mod.__path__ = [f"<memory>/{pkg}"]
            self._log(f"Пакет '{pkg}' уже в sys.modules")

        # ── Шаг 2: устанавливаем перехватчик для relative imports ────────
        # Когда __init__.pyd делает "from .parser import X", Python ищет
        # "atom.parser" через importlib. Регистрируем meta_path finder
        # который перенаправит этот поиск на наши загруженные модули.
        # ── Шаг 3: загружаем субмодули (всё кроме __init__) ────────────
        init_entry = None
        for module_name, data in self._entries:
            if module_name == "__init__":
                init_entry = (module_name, data)
                continue
            full_name = f"{pkg}.{module_name}"
            self._log(f"  Загружаем субмодуль '{full_name}'...")
            sub_loader = PydMemoryLoader(
                data,
                module_name       = full_name,
                suppress_debug    = self._suppress_debug,
                verbose           = self._verbose,
            )
            sub_mod = sub_loader.load()
            self._loaders[full_name] = sub_loader
            setattr(pkg_mod, module_name, sub_mod)
            self._log(f"  '{full_name}' загружен OK")

        # ── Шаг 4: загружаем __init__ последним ──────────────────────────
        # Finder устанавливается непосредственно перед exec-фазой __init__,
        # чтобы перехватывать relative imports именно во время их выполнения.
        if init_entry:
            module_name, data = init_entry
            self._log(f"  Загружаем '{pkg}.__init__'...")

            # Убеждаемся что pkg_mod в sys.modules имеет корректный __spec__
            # с submodule_search_locations — без этого relative import падает
            # с "attempted relative import with no known parent package"
            pkg_mod.__spec__ = importlib.machinery.ModuleSpec(pkg, loader=None)
            pkg_mod.__spec__.submodule_search_locations = list(pkg_mod.__path__)
            pkg_mod.__package__ = pkg
            sys.modules[pkg] = pkg_mod  # обновляем на случай если был заменён

            # Finder перехватывает "atom.parser" → уже загруженный модуль
            finder = _MemoryPackageFinder(pkg, self._loaders)
            sys.meta_path.insert(0, finder)
            try:
                init_loader = PydMemoryLoader(
                    data,
                    module_name             = pkg,
                    suppress_debug          = self._suppress_debug,
                    verbose                 = self._verbose,
                    register_in_sys_modules = False,
                )
                init_mod = init_loader.load()
            finally:
                if finder in sys.meta_path:
                    sys.meta_path.remove(finder)

            self._loaders[pkg] = init_loader

            # Копируем публичные атрибуты из __init__ в pkg_mod
            for attr_name, attr_val in vars(init_mod).items():
                if not attr_name.startswith("__") or attr_name in (
                    "__all__", "__version__", "__author__"
                ):
                    setattr(pkg_mod, attr_name, attr_val)

            self._log(f"  '__init__' загружен, атрибуты скопированы в пакет")
        else:
            self._log(f"  __init__.pyd не найден, пакет = набор субмодулей")

        self._package_module = pkg_mod
        self._log(f"Пакет '{pkg}' полностью загружен.")
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
        self._pkg     = package_name
        self._loaders = loaders

    def find_spec(self, fullname, path, target=None):
        # Интересуют только субмодули нашего пакета
        if not fullname.startswith(self._pkg + "."):
            return None
        # Если уже загружен — возвращаем spec для него
        if fullname in sys.modules:
            mod  = sys.modules[fullname]
            spec = importlib.machinery.ModuleSpec(
                fullname,
                loader  = _AlreadyLoadedLoader(mod),
                origin  = getattr(mod, "__file__", f"<memory>/{fullname}"),
            )
            return spec
        return None

    def find_module(self, fullname, path=None):
        return None


class _AlreadyLoadedLoader:
    """Loader-заглушка для модулей уже загруженных в память."""

    def __init__(self, module):
        self._module = module

    def create_module(self, spec):
        return self._module

    def exec_module(self, module):
        pass  # уже выполнен