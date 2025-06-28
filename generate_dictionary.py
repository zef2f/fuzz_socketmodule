#!/usr/bin/env python3
"""
Создаёт словарь libFuzzer для строковых/байтовых полей сетевого API.

▪ Если указать имя файла-аргумент, словарь будет записан туда.
▪ Без аргумента создаётся ./socket.dict
"""

from pathlib import Path
import sys

TOKENS = [
    "GET ", "POST ", "HEAD ",
    "HTTP/1.0\\r\\n", "HTTP/1.1\\r\\n", "\\r\\n\\r\\n",
    "Host:", "User-Agent:", "Content-Length:",
    "127.0.0.1", "::1", "/etc/passwd",
    "\\x00\\x50",          # порт  80 (BE)
    "\\x1F\\x90",          # порт 8080
    "\\x02",               # AF_INET
    "\\x0A",               # AF_INET6
]

def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("socket.dict")
    path.write_text("\n".join(f'"{t}"' for t in TOKENS) + "\n")
    print(f"✓ Словарь сохранён в {path.resolve()} ({len(TOKENS)} токенов)")

if __name__ == "__main__":
    main()
