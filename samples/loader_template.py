# ===== ЗАГРУЗЧИК ЗАШИФРОВАННЫХ МОДУЛЕЙ =====
import sys
import os
import io
import zipfile
import base64
import importlib.abc
import importlib.machinery
import importlib.util
import types
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# pyd_loader должен лежать рядом или быть установлен
from pyd_loader import PydMemoryLoader, PydPackageLoader


def deobf_pwd(obf_b64, xor_key):
    xored = base64.urlsafe_b64decode(obf_b64)
    orig_bytes = bytes(b ^ xor_key for b in xored)
    return orig_bytes.decode('utf-8')


class EncryptedModuleLoader(importlib.abc.Loader):
    def __init__(self, payload):
        self.password = deobf_pwd("{password_obf_b64}", {password_xor_key})

        # { normalized_module_name: bytes }
        # Например: "atom.__init__", "atom.parser", "mymodule"
        self.modules: dict[str, bytes] = {}

        # { package_name: [submodule_short_name, ...] }
        # Например: "atom": ["parser", "reader"]
        self.package_contents: dict[str, list[str]] = {}

        # Кэш уже загруженных модулей { full_name: ModuleType }
        self._loaded_modules: dict[str, types.ModuleType] = {}

        self._load_payload(payload)

    # ── Распаковка и расшифровка zip ─────────────────────────────────────────

    def _load_payload(self, payload):
        try:
            salt           = payload[:16]
            encrypted_data = payload[16:]

            kdf = PBKDF2HMAC(
                algorithm  = hashes.SHA256(),
                length     = 32,
                salt       = salt,
                iterations = 100000,
            )
            key    = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
            cipher = Fernet(key)

            zip_data       = cipher.decrypt(encrypted_data)
            self.zip_file  = zipfile.ZipFile(io.BytesIO(zip_data), 'r')

            # Читаем список файлов и строим карту модулей
            for name in self.zip_file.namelist():
                module_data     = self.zip_file.read(name)
                # "atom/parser.cp312-win_amd64.pyd" → "atom.parser"
                normalized_name = (
                    name
                    .replace('/', '.')
                    .replace('\\', '.')
                    .split('.cp')[0]   # убираем ".cp312-win_amd64"
                    .rstrip('.')
                )
                # Убираем суффикс .pyd если остался
                if normalized_name.endswith('.pyd'):
                    normalized_name = normalized_name[:-4]

                self.modules[normalized_name] = module_data

                # Регистрируем пакет если это __init__
                if normalized_name.endswith('.__init__'):
                    package_name = normalized_name[:-9]  # убираем ".__init__"
                    if package_name not in self.package_contents:
                        self.package_contents[package_name] = []

            # Строим список субмодулей для каждого пакета
            for module_name in self.modules:
                if module_name.endswith('.__init__'):
                    continue
                parts = module_name.split('.')
                if len(parts) > 1:
                    package = '.'.join(parts[:-1])
                    if package in self.package_contents:
                        subname = parts[-1]
                        if subname not in self.package_contents[package]:
                            self.package_contents[package].append(subname)

        except Exception as e:
            print(f"Ошибка загрузки payload: {e}")
            raise

    # ── Загрузка отдельного .pyd через PydMemoryLoader ───────────────────────

    def _load_single_pyd(self, module_name: str, data: bytes) -> types.ModuleType:
        """Загружает один .pyd файл из байт через PydMemoryLoader."""
        if module_name in self._loaded_modules:
            return self._loaded_modules[module_name]

        loader = PydMemoryLoader(
            data,
            module_name             = module_name,
            register_in_sys_modules = True,
            suppress_debug          = True,
        )
        mod = loader.load()
        self._loaded_modules[module_name] = mod
        return mod

    # ── Загрузка пакета через PydPackageLoader ────────────────────────────────

    def _load_package_pyd(self, package_name: str) -> types.ModuleType:
        """Загружает пакет (несколько .pyd) через PydPackageLoader."""
        if package_name in self._loaded_modules:
            return self._loaded_modules[package_name]

        pkg_loader = PydPackageLoader(
            package_name,
            suppress_debug = True,
        )

        # Сначала добавляем субмодули
        for subname in self.package_contents[package_name]:
            full_name = f"{package_name}.{subname}"
            if full_name in self.modules:
                pkg_loader.add(subname, self.modules[full_name])

        # Потом __init__ — PydPackageLoader всегда грузит его последним
        init_name = f"{package_name}.__init__"
        if init_name in self.modules:
            pkg_loader.add("__init__", self.modules[init_name])

        pkg = pkg_loader.load()
        self._loaded_modules[package_name] = pkg

        # Кэшируем субмодули отдельно
        for full_name, sub_mod in pkg_loader.submodules.items():
            if sub_mod is not None:
                self._loaded_modules[full_name] = sub_mod

        return pkg

    # ── importlib.abc.Loader protocol ────────────────────────────────────────

    def create_module(self, spec):
        # Если модуль уже загружен — возвращаем его напрямую
        if spec.name in self._loaded_modules:
            return self._loaded_modules[spec.name]
        return None

    def exec_module(self, module):
        name = module.__name__

        # Уже загружен (например субмодуль пакета)
        if name in self._loaded_modules:
            _copy_attrs(self._loaded_modules[name], module)
            return

        # Пакет с несколькими .pyd
        if name in self.package_contents:
            pkg = self._load_package_pyd(name)
            _copy_attrs(pkg, module)
            # Переносим __path__ чтобы relative imports работали
            if hasattr(pkg, '__path__'):
                module.__path__ = pkg.__path__
            return

        # Одиночный .pyd
        if name in self.modules:
            mod = self._load_single_pyd(name, self.modules[name])
            _copy_attrs(mod, module)
            return

        raise ImportError(f"Модуль '{name}' не найден в зашифрованном payload")


# ── Вспомогательная функция копирования атрибутов ────────────────────────────

def _copy_attrs(src: types.ModuleType, dst: types.ModuleType) -> None:
    """Копирует публичные атрибуты из src в dst."""
    for attr in dir(src):
        if not attr.startswith('__'):
            try:
                setattr(dst, attr, getattr(src, attr))
            except (AttributeError, TypeError):
                pass


# ── Finder ────────────────────────────────────────────────────────────────────

class EncryptedModuleFinder(importlib.abc.MetaPathFinder):
    def __init__(self, loader: EncryptedModuleLoader):
        self.loader = loader

    def find_spec(self, fullname, path, target=None):
        if fullname in self.loader.package_contents:
            return importlib.machinery.ModuleSpec(
                fullname,
                self.loader,
                origin     = f"encrypted://{fullname}",
                is_package = True,
            )

        if fullname in self.loader.modules:
            return importlib.machinery.ModuleSpec(
                fullname,
                self.loader,
                origin     = f"encrypted://{fullname}",
                is_package = False,
            )

        return None


# ── Точка входа ───────────────────────────────────────────────────────────────

def main_executor(payload):
    loader = EncryptedModuleLoader(payload)

    # Убираем стандартные файловые finder-ы — всё грузится из памяти
    sys.meta_path = [
        f for f in sys.meta_path
        if not isinstance(f, (importlib.machinery.PathFinder,
                               importlib.machinery.FileFinder))
    ]
    sys.meta_path.insert(0, EncryptedModuleFinder(loader))

    if '' not in sys.path:
        sys.path.insert(0, '')

    try:
        import main
    except ImportError as e:
        print(f"Ошибка импорта: {e}")
        sys.exit(1)

    if hasattr(main, 'main'):
        main.main()
    else:
        print("В модуле нет функции main()")