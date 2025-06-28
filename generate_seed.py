#!/usr/bin/env python3
"""
Создаёт или обновляет corpus/ для fuzz_socketmodule:

  • 4 базовых семени
  • 2 PoC для CVE-2014-1912 и CVE-2015-0235
  • 10 edge-case семян (помогают ловить новые баги)

Запуск без аргументов ⇒ ./corpus
           с аргументом ⇒ указанный каталог
"""

from pathlib import Path
from textwrap import dedent
import os, sys, random, subprocess, tempfile

# ───────── 1. БАЗОВЫЕ СЕМЕНА (4) ─────────
BASE_SEEDS = [
    dedent("""\
        header { socks { id: 0 family: 2 type: 1 } }           # пустой TCP-сокет
    """),

    dedent("""\
        header {
          socks {
            id: 1
            family: 10   # AF_INET6
            type: 2      # SOCK_DGRAM
            preload_send: "GET / HTTP/1.0\\r\\n\\r\\n"
          }
        }
        command { sock_socket { family: 2 type: 1 proto: 0 target_id: 3 } }
    """),

    dedent("""\
        command { inet_pton { family: 2 text: "127.0.0.1" } }
        command { inet_ntop { family: 2 packed: "\\x7f\\x00\\x00\\x01" } }
    """),

    dedent("""\
        command { sock_socket { family: 999 type: 3 proto: 0 target_id: 0 } }
        command { sock_close  { id: 0 } }
    """),
]

# ───────── 2. CVE-СПЕЦИФИЧЕСКИЕ (2) ─────────
payload_2014 = "A" * 300
SEED_CVE2014 = dedent(f"""\
    header {{
      socks {{ id: 0 family: 2 type: 2 payload: "{payload_2014}" }}   # UDP
    }}
    command {{ sock_recvfrom_into {{ id: 0 nbytes: 8 }} }}
""")

long_numeric_host = "1234567890" * 26
SEED_CVE2015 = dedent(f"""\
    command {{ gethostbyname {{ name: "{long_numeric_host}" }} }}
""")

CVE_SEEDS = [SEED_CVE2014, SEED_CVE2015]

# ───────── 3. ДОПОЛНИТЕЛЬНЫЕ EDGE-CASES (10) ─────────
SEED_IDN = dedent("""\
    command { getaddrinfo {
        host: "xn--wgv71a119e.xn--wgv71a119e.xn--wgv71a119e.xn--wgv71a119e"
        family: 0               # AF_UNSPEC
        flags: 66               # AI_IDN | AI_CANONNAME
    } }
""")

SEED_SERVICE = dedent("""\
    command { getaddrinfo { host: "localhost"
                            service: "999999999999999999"
                            family: 2 type: 1 } }
""")

SEED_FD_LIFECYCLE = dedent("""\
    command { sock_socketpair { family: 2 type: 1 proto: 0 id1: 10 id2: 11 } }
    command { sock_dup        { src_id: 10 dst_id: 20 } }
    command { sock_close      { id: 10 } }
    command { sock_close      { id: 20 } }
""")

SEED_IPV6_BROKEN = dedent("""\
    command { inet_pton { family: 10 text: "1:2:3:4:5:6:7:8:9" } }
""")

large_msg = "B" * 60000
SEED_SENDMSG_LARGE = dedent(f"""\
    header {{ socks {{ id: 0 family: 2 type: 2 }} }}
    command {{ sock_sendmsg {{ id: 0 data: "{large_msg}" flags: 0 }} }}
""")

tiny_payload = "C" * 64
SEED_RECVMSG_ANC = dedent(f"""\
    header {{ socks {{ id: 0 family: 2 type: 2 payload: "{tiny_payload}" }} }}
    command {{ sock_recvmsg_into {{ id: 0 nbytes: 16 ancbufsize: 4096 flags: 0 }} }}
""")

big_optval = "D" * 256
SEED_SETSOCKOPT = dedent(f"""\
    header {{ socks {{ id: 0 family: 2 type: 1 }} }}
    command {{ sock_setsockopt {{ id: 0 level: 1 opt: 2 val: "{big_optval}" }} }}
""")

long_path = "/tmp/" + "subdir_" * 20 + "sock"
SEED_AFUNIX_LONG = dedent(f"""\
    header {{ socks {{ id: 0 family: 1 type: 1 }} }}
    command {{ sock_bind {{ id: 0 addr: "{long_path}" }} }}
""")

ipv4_sockaddr = "\\x02\\x00\\x04\\xd2\\x7f\\x00\\x00\\x01"  # AF_INET, port 1234, 127.0.0.1
SEED_CONNECT_MISMATCH = dedent(f"""\
    header {{ socks {{ id: 0 family: 10 type: 1 }} }}
    command {{ sock_connect_ex {{ id: 0 addr: "{ipv4_sockaddr}" }} }}
""")

SEED_SHUTDOWN_INVALID = dedent("""\
    header { socks { id: 0 family: 2 type: 1 } }
    command { sock_shutdown { id: 0 how: 123 } }
""")

EXTRA_EDGE_SEEDS = [
    SEED_IDN,
    SEED_SERVICE,
    SEED_FD_LIFECYCLE,
    SEED_IPV6_BROKEN,
    SEED_SENDMSG_LARGE,
    SEED_RECVMSG_ANC,
    SEED_SETSOCKOPT,
    SEED_AFUNIX_LONG,
    SEED_CONNECT_MISMATCH,
    SEED_SHUTDOWN_INVALID,
]

# ───────── 4. ЗАПИСЬ СЕМЯН ─────────
def write_text_seeds(out: Path) -> None:
    all_seeds = BASE_SEEDS + CVE_SEEDS + EXTRA_EDGE_SEEDS
    for idx, text in enumerate(all_seeds, 1):
        (out / f"seed{idx:02d}.txt").write_text(text)

def write_binary_seeds(out: Path) -> None:
    """Маленькие .pb (htons) — быстрый fuzz десериализатора."""
    proto = Path(__file__).with_name("socket_api.proto")
    if not proto.exists():
        return
    for _ in range(50):
        val = random.randint(0, 65535)
        msg = f'command{{ htons{{ val:{val} }} }}'
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(msg)
        bin_path = out / f"seed_htons_{val:05}.pb"
        subprocess.run(
            ["protoc", "--encode=Command",
             f"--proto_path={proto.parent}", proto.name],
            stdin=open(tmp.name, "r"),
            stdout=open(bin_path, "wb"),
            check=True,
        )
        os.unlink(tmp.name)

def main() -> None:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("corpus")
    out_dir.mkdir(parents=True, exist_ok=True)
    write_text_seeds(out_dir)
    try:
        write_binary_seeds(out_dir)
    except Exception as e:
        print(f"[!] пропускаю бинарные семена: {e}")
    print(f"✓ corpus обновлён в {out_dir.resolve()}  "
          f"(базовые {len(BASE_SEEDS)}, CVE {len(CVE_SEEDS)}, extras {len(EXTRA_EDGE_SEEDS)})")

if __name__ == "__main__":
    main()
