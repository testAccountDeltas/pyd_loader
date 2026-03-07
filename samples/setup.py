from setuptools import setup, Extension, find_packages
from Cython.Build import cythonize
from Cython.Distutils import build_ext
import os
import sys
import json
import subprocess
import argparse
import shutil
import random
import string
import time
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import re

def load_config(config_path, launcher_dir):
    """Загружает конфигурацию из JSON файла"""
    launcher_folder_name = os.path.basename(launcher_dir)
    
    default_config = {
        "project_name": "build.exe",
        "compile_dirs": [
            "atom",
            "core", 
            "memory"
        ],
        "hidden_imports": [
            'concurrent', 'concurrent.futures', 'threading', 'queue', 
            'multiprocessing', 'enum', 'dataclasses', 'json', 'struct', 
            'logging', 'traceback', 'cProfile', 'ctypes', 'tempfile',
            'zipfile', 'base64', 'cryptography', 'io'
        ],
        "additional_args": []
    }
    
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
            default_config.update(user_config)
            print(f"Загружена конфигурация из: {config_path}")
    else:
        print(f"Конфигурация не найдена: {config_path}")
        print("Используются настройки по умолчанию")
        print(f"Папка с launcher: {launcher_folder_name}")
    
    return default_config

def parse_args():
    """Парсит только наши кастомные аргументы"""
    parser = argparse.ArgumentParser(description='Универсальный сборщик проекта', add_help=False)
    parser.add_argument('--our-config', dest='config', help='Путь к файлу конфигурации')
    parser.add_argument('--our-name', dest='name', help='Имя выходного exe файла')
    parser.add_argument('--our-launcher', dest='launcher', help='Имя launcher.py файла')
    parser.add_argument('--launcher-dir', help='Directory where build was launched')
    
    args, unknown = parser.parse_known_args()
    return args, unknown

def get_build_id():
    """Генерирует уникальный ID для этой сборки"""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    random_part = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    return f"{timestamp}_{random_part}"

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """Генерирует ключ шифрования из пароля"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def create_encrypted_payload(pyd_files):
    """Создает зашифрованный payload со всеми .pyd файлами"""
    import io
    import zipfile
    from cryptography.fernet import Fernet
    
    # Генерируем соль
    salt = os.urandom(16)
    
    # Если пароль не указан, генерируем случайный
    password = base64.b64encode(os.urandom(32)).decode('ascii')[:32]
    print(f"Сгенерирован случайный пароль: {password}")
    
    # Создаем ключ из пароля
    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)
    
    # Создаем ZIP архив в памяти
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for module_name, file_path in pyd_files.items():
            # Сохраняем с правильной структурой папок
            arcname = module_name.replace('.', '/') + '.pyd'
            zip_file.write(file_path, arcname)
            print(f"  Добавлен в архив: {arcname}")
    
    # Шифруем ZIP архив
    zip_data = zip_buffer.getvalue()
    encrypted_data = cipher.encrypt(zip_data)
    
    # Формируем финальный payload: [salt(16)][encrypted_data]
    payload = salt + encrypted_data
    
    return payload, password

def create_minimal_stub(compiled_launcher_module_name, payload_b64, main_executor):
    """Создает минимальный загрузчик для скомпилированного лаунчера"""
    
    # Генерируем случайное имя для загрузчика
    stub_name = ''.join(random.choices(string.ascii_letters, k=16))
    if isinstance(payload_b64, bytes):
        payload_repr = repr(payload_b64)
    else:
        payload_repr = repr(payload_b64.encode('ascii'))
    stub_code = f'''# -*- coding: utf-8 -*-
import sys
import os

try:
    import {compiled_launcher_module_name}
except ImportError as e:
    print(f"[!] Ошибка импорта: {{e}}")
    sys.exit(1)

if __name__ == "__main__":
    if hasattr({compiled_launcher_module_name}, '{main_executor}'):
        {compiled_launcher_module_name}.{main_executor}({payload_repr})
    else:
        sys.exit(1)
'''
    
    return stub_code, stub_name

def compile_modified_launcher(modified_launcher_path, project_root):
    """Компилирует модифицированный лаунчер через Cython"""
    
    print("\n" + "="*60)
    print("КОМПИЛЯЦИЯ MODIFIED LAUNCHER")
    print("="*60)
    
    # Получаем имя файла без расширения
    launcher_basename = os.path.basename(modified_launcher_path)
    launcher_name = os.path.splitext(launcher_basename)[0]
    
    # Создаем Extension для компиляции
    ext = Extension(
        launcher_name,
        [modified_launcher_path],
        extra_compile_args=["/O2", "/Gy"],
        extra_link_args = ["/LTCG", "/OPT:REF", "/OPT:ICF"]
    )
    
    try:
        # Компилируем
        setup(
            ext_modules=cythonize(
                [ext],
                compiler_directives={
                    'language_level': "3",
                    'boundscheck': False,
                    'initializedcheck': False,
                    'nonecheck': False,
                },
                annotate=False,
                gdb_debug=False,
            ),
            cmdclass={'build_ext': build_ext},
            script_args=['build_ext', '--inplace'],
        )
        # Ищем скомпилированный файл
        compiled_file = None
        for file in os.listdir(project_root):
            if file.startswith(launcher_name) and file.endswith('.pyd'):
                compiled_file = os.path.join(project_root, file)
                break
        
        if compiled_file:
            print(f"Лаунчер скомпилирован: {compiled_file}")
            
            # Получаем имя модуля (без .pyd)
            module_name = os.path.splitext(os.path.basename(compiled_file))[0]
            
            # Очищаем имя модуля от суффиксов Python/Cython
            clean_module_name = re.sub(r'\.cp\d+-[^.]+', '', module_name)
            
            return compiled_file, clean_module_name
        else:
            print("Не удалось найти скомпилированный файл")
            return None, None
            
    except SystemExit:
        # Ищем файл после SystemExit
        for file in os.listdir(project_root):
            if file.startswith(launcher_name) and file.endswith('.pyd'):
                compiled_file = os.path.join(project_root, file)
                module_name = os.path.splitext(os.path.basename(compiled_file))[0]
                clean_module_name = re.sub(r'\.cp\d+-[^.]+', '', module_name)
                return compiled_file, clean_module_name
        return None, None

def get_pyinstaller_path():
    """
    Возвращает путь к pyinstaller в текущем виртуальном окружении
    """
    python_dir = os.path.dirname(sys.executable)
    
    pyinstaller_path = os.path.join(python_dir, 'Scripts', 'pyinstaller.exe')
    if os.path.exists(pyinstaller_path):
        return pyinstaller_path
    
    pyinstaller_path = os.path.join(python_dir, 'bin', 'pyinstaller')
    if os.path.exists(pyinstaller_path):
        return pyinstaller_path

    return 'pyinstaller'

def should_exclude_path(path):
    """Проверяет, нужно ли исключить путь"""
    
    # Паттерны для исключения
    exclude_patterns = [
        'Lib\\site-packages',
        'lib\\site-packages',
        'Lib/site-packages',
        'lib/site-packages',
        'site-packages',
        'dist-packages',
        '__pycache__',
        '.venv',
        'venv',
        'env',
        'Scripts',
        'bin',
        'tests',
        'pythonmemorymodule',
        'windows',
    ]

    # Проверяем по паттернам
    path_lower = path.lower()
    for pattern in exclude_patterns:
        if pattern.lower() in path_lower:
            return True
    
    return False

def main():
    # Парсим аргументы
    our_args, _ = parse_args()
    
    # Генерируем уникальный ID сборки
    build_id = get_build_id()
    print(f"\nBuild ID: {build_id}")
    
    # Определяем корень проекта
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    # Определяем директорию запуска
    launcher_dir = our_args.launcher_dir
    
    print(f"Корень проекта: {project_root}")
    print(f"Папка запуска: {launcher_dir}")
    
    # Определяем путь к конфигурации
    if our_args.config:
        config_path = os.path.join(launcher_dir, our_args.config) if not os.path.isabs(our_args.config) else our_args.config
    else:
        config_path = os.path.join(launcher_dir, 'build_config.json')
    
    # Загружаем конфигурацию
    config = load_config(config_path, launcher_dir)
    
    # Переопределяем из аргументов
    if our_args.name:
        config['project_name'] = our_args.name
    
    # Переходим в корень проекта
    os.chdir(project_root)
    
    # ========== КОМПИЛЯЦИЯ CYTHON ==========
    print("\n" + "="*60)
    print("КОМПИЛЯЦИЯ CYTHON")
    print("="*60)
    
    # Собираем все .py файлы для компиляции
    ext_modules = []
    
    for dir_path in [launcher_dir] + config['compile_dirs']:
        full_path = os.path.join(project_root, dir_path)
        if os.path.exists(full_path):
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    if file.endswith('.py') and file != 'setup.py' and file != 'loader_template.py':
                        py_path = os.path.join(root, file)
                        rel_path = os.path.relpath(py_path, project_root)
                        if should_exclude_path(rel_path):
                            continue
                        module_name = rel_path.replace('.py', '').replace('\\', '.').replace('/', '.')
                        ext_modules.append(Extension(module_name, [py_path], extra_compile_args=["/O2", "/Gy"], extra_link_args = ["/LTCG", "/OPT:REF", "/OPT:ICF"]))
                        print(f"  Добавлен модуль: {module_name}")
    
    print(f"\nНайдено файлов для компиляции: {len(ext_modules)}")
    
    if not ext_modules:
        print("Нет файлов для компиляции!")
        return
    
    # Компилируем
    try:
        setup(
            ext_modules=cythonize(
                ext_modules,
                compiler_directives={
                    'language_level': "3",
                    'boundscheck': False,
                    'initializedcheck': False,
                    'nonecheck': False,
                },
                annotate=False,
                gdb_debug=False,
            ),
            cmdclass={'build_ext': build_ext},
            script_args=['build_ext', '--inplace'],
        )
        print(f"\nКомпиляция завершена")
    except SystemExit:
        pass
    
    # ========== СБОР .PYD ФАЙЛОВ ==========
    suffix = '.pyd'
    pyd_files = {}
    
    for root, _, files in os.walk(project_root):
        for file in files:
            if file.endswith(suffix):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, project_root)
                if should_exclude_path(rel_path):
                    continue
                module_name = rel_path.replace(suffix, '').replace('\\', '.').replace('/', '.')
                # Очищаем имя модуля от суффиксов Python/Cython
                clean_module_name = re.sub(r'\.cp\d+-[^.]+', '', module_name)
                pyd_files[clean_module_name] = full_path
    
    print(f"\nСкомпилировано .pyd файлов: {len(pyd_files)}")
    
    # ========== СОЗДАНИЕ ЗАШИФРОВАННОГО PAYLOAD ==========
    print("\n" + "="*60)
    print("СОЗДАНИЕ ЗАШИФРОВАННОГО PAYLOAD")
    print("="*60)
    
    payload, used_password = create_encrypted_payload(pyd_files)
    
    # ========== СОЗДАНИЕ ЗАГРУЗЧИКА ==========
    print("\n" + "="*60)
    print("СОЗДАНИЕ ЗАГРУЗЧИКА")
    print("="*60)
    
    # Генерируем случайное имя для модифицированного лаунчера
    random_name = ''.join(random.choices(string.ascii_letters, k=32))
    modified_launcher = os.path.join(launcher_dir, random_name + '.py')
    
    # Создаем загрузчик из шаблона
    template_path = os.path.join(os.path.dirname(__file__), 'loader_template.py')
    with open(template_path, 'r', encoding='utf-8') as f:
        loader_code = f.read()
    
    # Обрабатываем пароль
    xor_key = random.randint(0x20, 0x7E)
    obf_pwd = ''.join(chr(ord(c) ^ xor_key) for c in used_password)
    obf_b64 = base64.urlsafe_b64encode(obf_pwd.encode('utf-8')).decode('ascii')
    
    loader_code = loader_code.replace('{password_obf_b64}', obf_b64).replace('{password_xor_key}', str(xor_key))
    
    main_executor = ''.join(random.choices(string.ascii_letters, k=random.randint(3,8)))
    loader_code = loader_code.replace('main_executor', main_executor)
    
    # Сохраняем модифицированный лаунчер
    with open(modified_launcher, 'w', encoding='utf-8') as f:
        f.write(loader_code)
    
    print(f"Создан модифицированный лаунчер: {modified_launcher}")
    
    # ========== КОМПИЛЯЦИЯ MODIFIED LAUNCHER ==========
    compiled_launcher, compiled_module_name = compile_modified_launcher(modified_launcher, project_root)
    
    if not compiled_launcher:
        print("Не удалось скомпилировать лаунчер")
        return
    
    # ========== СОЗДАНИЕ МИНИМАЛЬНОГО СТАБА ==========
    stub_code, stub_name = create_minimal_stub(compiled_module_name, payload, main_executor)
    stub_path = os.path.join(launcher_dir, stub_name + '.py')
    
    with open(stub_path, 'w', encoding='utf-8') as f:
        f.write(stub_code)
    
    print(f"Создан минимальный стаб: {stub_path}")
    
    # ========== СБОРКА EXE ==========
    print("\n" + "="*60)
    print("СБОРКА EXE")
    print("="*60)
    
    if not os.path.exists(stub_path):
        print(f"Ошибка: {stub_path} не найден!")
        return
    
    exe_name = f"{config['project_name']}_{build_id}"
    
    PyInstaller = get_pyinstaller_path()
    cmd = [
        PyInstaller, '--onefile', '--clean', '--noconfirm',
        '--name', exe_name,
        '--distpath', os.path.join(launcher_dir, 'dist'),
        '--workpath', os.path.join(launcher_dir, 'build'),
        '--specpath', launcher_dir,
    ]
    
    # Добавляем скомпилированный лаунчер как data файл
    cmd.extend(['--add-data', f"{compiled_launcher}{os.pathsep}."])
    
    for imp in config['hidden_imports']:
        cmd.extend(['--hidden-import', imp])
    
    cmd.extend(config['additional_args'])
    cmd.append(stub_path)
    
    print("\nКоманда сборки:")
    print(' '.join(cmd))
    print()
    
    result = subprocess.run(cmd, shell=True, cwd=launcher_dir)
    
    if result.returncode == 0:
        exe_path = os.path.join(launcher_dir, 'dist', f"{exe_name}.exe")
        
        if os.path.exists(exe_path):
            size = os.path.getsize(exe_path)
            md5 = hashlib.md5(open(exe_path, 'rb').read()).hexdigest()
            
            print(f"\nГОТОВО!")
            print(f"Файл: {exe_path}")
            print(f"Размер: {size} байт")
            print(f"MD5: {md5}")
            print(f"Build ID: {build_id}")
            
            info = {
                'build_id': build_id,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'exe_name': f"{exe_name}.exe",
                'size': size,
                'md5': md5,
                'password': used_password,
                'payload_size': len(payload),
                'compiled_launcher': compiled_module_name,
                'pyd_files': list(pyd_files.keys())
            }
            
            info_path = os.path.join(launcher_dir, 'dist', f"{exe_name}_info.json")
            with open(info_path, 'w') as f:
                json.dump(info, f, indent=2)
            print(f"📄 Инфо: {info_path}")
    else:
        print(f"\nОшибка сборки! Код: {result.returncode}")
    
    # ========== ОЧИСТКА ВРЕМЕННЫХ ФАЙЛОВ ==========
    print("\n" + "="*60)
    print("ОЧИСТКА ВРЕМЕННЫХ ФАЙЛОВ")
    print("="*60)
    

    

    for p in [stub_path, modified_launcher]:
        if os.path.exists(p):
            try:
                print(f"Удален файл кэша: {p}")
                os.remove(p)
            except:
                pass


    for root, _, files in os.walk(project_root):
        for file in files:
            if file.endswith('.pyd') or file.endswith('.c') or file.endswith('.spec'):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, project_root)
                if not should_exclude_path(rel_path):
                    try:
                        os.remove(file_path)
                        print(f"Удален файл: {rel_path}")
                    except Exception as e:
                        print(f"Ошибка удаления {rel_path}: {e}")


if __name__ == '__main__':
    main()