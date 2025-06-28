#!/usr/bin/env python3
"""
Полностью валидный seed-корпус для fuzz_socketmodule.
Каждый seed пишется в TextFormat (.txt) и бинарный wire-формат (.pb).
"""

import random, re, subprocess, sys, tempfile
from pathlib import Path
from textwrap import dedent

PROTO = Path(__file__).with_name("socket_api.proto")
ENCODE = ["protoc", f"--proto_path={PROTO.parent}", "--encode=Program", PROTO.name]

def _clean(txt: str) -> str:
    txt = re.sub(r"#.*", "", txt)                 # убираем #-комменты
    txt = txt.replace("header", "init").replace("command", "cmds")
    txt = txt.replace("payload:", "preload_send:")       # главное исправление
    txt = dedent(txt)
    return "\n".join(l.rstrip() for l in txt.splitlines() if l.strip()) + "\n"

def _encode(text: str, dst: Path) -> None:
    subprocess.run(ENCODE, input=text.encode(), stdout=dst.open("wb"), check=True)

def _pair(idx: int, raw: str, out: Path, prefix="seed") -> None:
    txt = out / f"{prefix}{idx:02d}.txt"
    pb  = out / f"{prefix}{idx:02d}.pb"
    cleaned = _clean(raw)
    txt.write_text(cleaned)
    _encode(cleaned, pb)

# ───── базовые / CVE / edge-cases ─────
PAYLOAD_2014 = "A" * 300
LONG_NUM     = "1234567890" * 26
EXTRA_PATH   = "/tmp/" + "subdir_" * 20 + "sock"
BIG_OPTVAL   = "D" * 256
LARGE_MSG    = "B" * 60000
TINY_PAYLOAD = "C" * 64
IPV4_SOCKADDR= "\\x02\\x00\\x04\\xd2\\x7f\\x00\\x00\\x01"

SEEDS = [
    # 4 базовых
    "header { socks { id:0 family:2 type:1 } }",
    """header { socks { id:1 family:10 type:2 preload_send:"GET / HTTP/1.0\\r\\n\\r\\n" } }
       command { sock_socket { family:2 type:1 proto:0 target_id:3 } }""",
    """command { inet_pton { family:2 text:"127.0.0.1" } }
       command { inet_ntop { family:2 packed:"\\x7f\\x00\\x00\\x01" } }""",
    """command { sock_socket { family:999 type:3 proto:0 target_id:0 } }
       command { sock_close  { id:0 } }""",

    # 2 CVE
    f"""header {{ socks {{ id:0 family:2 type:2 preload_send:"{PAYLOAD_2014}" }} }}
        command {{ sock_recvfrom_into {{ id:0 nbytes:8 }} }}""",
    f"""command {{ gethostbyname {{ name:"{LONG_NUM}" }} }}""",

    # 10 edge-cases
    """command { getaddrinfo { host:"xn--wgv71a119e.xn--wgv71a119e.xn--wgv71a119e.xn--wgv71a119e"
                               family:0 flags:66 } }""",
    """command { getaddrinfo { host:"localhost" service:"999999999999999999" family:2 type:1 } }""",
    """command { sock_socketpair { family:2 type:1 proto:0 id1:10 id2:11 } }
       command { sock_dup { src_id:10 dst_id:20 } }
       command { sock_close { id:10 } }
       command { sock_close { id:20 } }""",
    """command { inet_pton { family:10 text:"1:2:3:4:5:6:7:8:9" } }""",
    f"""header {{ socks {{ id:0 family:2 type:2 }} }}
        command {{ sock_sendmsg {{ id:0 data:"{LARGE_MSG}" flags:0 }} }}""",
    f"""header {{ socks {{ id:0 family:2 type:2 preload_send:"{TINY_PAYLOAD}" }} }}
        command {{ sock_recvmsg_into {{ id:0 nbytes:16 ancbufsize:4096 flags:0 }} }}""",
    f"""header {{ socks {{ id:0 family:2 type:1 }} }}
        command {{ sock_setsockopt {{ id:0 level:1 opt:2 val:"{BIG_OPTVAL}" }} }}""",
    f"""header {{ socks {{ id:0 family:1 type:1 }} }}
        command {{ sock_bind {{ id:0 addr:"{EXTRA_PATH}" }} }}""",
    f"""header {{ socks {{ id:0 family:10 type:1 }} }}
        command {{ sock_connect_ex {{ id:0 addr:"{IPV4_SOCKADDR}" }} }}""",
    """header { socks { id:0 family:2 type:1 } }
       command { sock_shutdown { id:0 how:123 } }""",
]

def _write_htons(out: Path, n: int = 50) -> None:
    for _ in range(n):
        val = random.randint(0, 65535)
        text = f"cmds {{ htons {{ val:{val} }} }}"
        _encode(_clean(text), out / f"seed_htons_{val:05}.pb")

def main() -> None:
    if not PROTO.exists():
        sys.exit("socket_api.proto not found")
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("corpus")
    out.mkdir(parents=True, exist_ok=True)

    for f in out.glob("seed*.*"):                 # очистим старое
        f.unlink()

    for i, raw in enumerate(SEEDS, 1):
        _pair(i, raw, out)

    _write_htons(out)
    print(f"✓ {len(SEEDS)} текстовых + {len(SEEDS)} бинарных + 50 htons в {out.resolve()}")

if __name__ == "__main__":
    main()


