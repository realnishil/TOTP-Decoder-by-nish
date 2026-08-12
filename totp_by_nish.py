#!/usr/bin/env python3
"""
========================================================
  T O T P   D E C O D E R   //   offline OTP engine
  RFC 6238 implemented from scratch (no pyotp, no net)
========================================================
"""

import base64
import hashlib
import hmac
import os
import struct
import sys
import time


class C:
    GREEN = "\033[38;5;46m"
    DIM_GREEN = "\033[38;5;22m"
    CYAN = "\033[38;5;51m"
    MAGENTA = "\033[38;5;201m"
    YELLOW = "\033[38;5;226m"
    RED = "\033[38;5;196m"
    GREY = "\033[38;5;240m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    CLEAR = "\033[2J\033[H"
    HIDE_CURSOR = "\033[?25l"
    SHOW_CURSOR = "\033[?25h"


BANNER = f"""{C.GREEN}{C.BOLD}
  _____ ___ _____ ____    ____                     _
 |_   _/ _ \\_   _|  _ \\  |  _ \\  ___  ___ ___   __| | ___ _ __
   | || | | || | | |_) | | | | |/ _ \\/ __/ _ \\ / _` |/ _ \\ '__|
   | || |_| || | |  __/  | |_| |  __/ (_| (_) | (_| |  __/ |
   |_| \\___/ |_| |_|     |____/ \\___|\\___\\___/ \\__,_|\\___|_|
{C.RESET}{C.DIM}{C.GREEN}          [ offline RFC-6238 engine // zero network calls ]{C.RESET}
"""


def type_out(text, delay=0.006, color=C.GREEN):
    for ch in text:
        sys.stdout.write(f"{color}{ch}{C.RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    print()


def hexdump_line(label, data, color=C.MAGENTA):
    hexstr = data.hex() if isinstance(data, (bytes, bytearray)) else str(data)
    print(f"  {C.GREY}{label:<22}{C.RESET}{color}{hexstr}{C.RESET}")


# ---------------------------------------------------------------
#  CORE TOTP ALGORITHM  (RFC 6238 on top of HOTP / RFC 4226)
# ---------------------------------------------------------------
def hotp(secret_bytes: bytes, counter: int, digits: int = 6, algo=hashlib.sha1):
    counter_bytes = struct.pack(">Q", counter)                    # 8-byte big-endian counter
    mac = hmac.new(secret_bytes, counter_bytes, algo).digest()    # HMAC-SHA1 -> 20 bytes

    offset = mac[-1] & 0x0F                                       # dynamic truncation offset (0-15)
    truncated = mac[offset:offset + 4]
    code_int = struct.unpack(">I", truncated)[0] & 0x7FFFFFFF     # clear top bit
    otp = code_int % (10 ** digits)
    return str(otp).zfill(digits), counter_bytes, mac, offset, code_int


def totp(secret_b32: str, time_step: int = 30, digits: int = 6, t0: int = 0, verbose=False):
    secret_bytes = base64.b32decode(secret_b32.upper().replace(" ", ""), casefold=True)
    now = int(time.time())
    T = (now - t0) // time_step
    code, counter_bytes, mac, offset, code_int = hotp(secret_bytes, T, digits)
    remaining = time_step - (now % time_step)

    if verbose:
        print(f"\n{C.CYAN}{C.BOLD}[ STEP 1 ]{C.RESET} time counter  T = floor((unix_time - T0) / X)")
        hexdump_line("unix_time", now, C.YELLOW)
        hexdump_line("T (step index)", T, C.YELLOW)
        hexdump_line("counter (8B hex)", counter_bytes)

        print(f"\n{C.CYAN}{C.BOLD}[ STEP 2 ]{C.RESET} HMAC-SHA1(secret, counter)")
        hexdump_line("HMAC digest (20B)", mac)

        print(f"\n{C.CYAN}{C.BOLD}[ STEP 3 ]{C.RESET} dynamic truncation")
        hexdump_line("offset (low nibble)", offset, C.YELLOW)
        hexdump_line("4-byte slice", mac[offset:offset + 4])
        hexdump_line("masked 31-bit int", code_int, C.YELLOW)

        print(f"\n{C.CYAN}{C.BOLD}[ STEP 4 ]{C.RESET} mod 10^{digits}")
        print(f"  {C.GREY}{'OTP':<22}{C.RESET}{C.GREEN}{C.BOLD}{code}{C.RESET}\n")

    return code, remaining, time_step


def bar(remaining, total, width=30):
    filled = int(width * remaining / total)
    color = C.GREEN if remaining > total * 0.33 else (C.YELLOW if remaining > total * 0.15 else C.RED)
    return f"{color}{'█' * filled}{C.GREY}{'░' * (width - filled)}{C.RESET}"


def live_loop(secret_b32, digits=6, time_step=30, verbose_first=True):
    print(C.HIDE_CURSOR, end="")
    try:
        last_code = None
        first = True
        while True:
            code, remaining, total = totp(secret_b32, time_step, digits, verbose=(first and verbose_first))
            first = False
            if code != last_code:
                sys.stdout.write("\r" + " " * 80 + "\r")
            last_code = code

            line = (
                f"\r{C.BOLD}{C.WHITE}CODE:{C.RESET} "
                f"{C.BOLD}{C.GREEN}{code[:3]} {code[3:]}{C.RESET}   "
                f"{C.GREY}expires in{C.RESET} {C.YELLOW}{remaining:2d}s{C.RESET}  "
                f"{bar(remaining, total)}"
            )
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.25)
    except KeyboardInterrupt:
        print(f"\n{C.SHOW_CURSOR}{C.RED}[ session terminated by user ]{C.RESET}")
        sys.exit(0)


def main():
    os.system("")
    print(C.CLEAR, end="")
    print(BANNER)

    type_out(">> no wifi. no network. no problem.", delay=0.01, color=C.DIM_GREEN)
    print()

    secret = input(f"{C.CYAN}{C.BOLD}[?]{C.RESET} enter base32 secret key (from your QR setup): {C.GREEN}").strip()
    print(C.RESET, end="")

    if not secret:
        print(f"{C.RED}[!] no secret provided -- using demo key JBSWY3DPEHPK3PXP{C.RESET}")
        secret = "JBSWY3DPEHPK3PXP"

    try:
        base64.b32decode(secret.upper().replace(" ", ""), casefold=True)
    except Exception:
        print(f"{C.RED}[!] invalid base32 secret. exiting.{C.RESET}")
        sys.exit(1)

    type_out("[+] secret accepted. deriving shared key material...", delay=0.008, color=C.MAGENTA)
    time.sleep(0.3)
    type_out("[+] starting local clock sync check...", delay=0.008, color=C.MAGENTA)
    time.sleep(0.3)
    type_out("[+] engine online. computing codes every 30s, fully offline.\n", delay=0.008, color=C.GREEN)
    time.sleep(0.3)

    live_loop(secret)


if __name__ == "__main__":
    main()
