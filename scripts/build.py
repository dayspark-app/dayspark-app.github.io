#!/usr/bin/env python3
"""
Build & encrypt static PWA vault.

Reads private local sources from `content/`, compresses photos for mobile screens
(stripping EXIF GPS/camera metadata), packs texts + photos into a compact binary
bundle, and encrypts everything with AES-256-GCM (PBKDF2-HMAC-SHA256) into
`docs/vault.enc`.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from crypto_gcm import DEFAULT_ITERATIONS, seal_vault  # noqa: E402

CONTENT_DIR = ROOT_DIR / "content"
PHOTOS_DIR = CONTENT_DIR / "photos"
DOCS_DIR = ROOT_DIR / "docs"
VAULT_PATH = DOCS_DIR / "vault.enc"
PASS_FILE = ROOT_DIR / ".vault-pass"

ALLOWED_TAGS = {"момент", "тренировка", "старт", "идея"}
ALLOWED_STATUSES = {"active", "pause", "sick"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def strip_jpeg_metadata(jpeg_bytes: bytes) -> bytes:
    """Strip EXIF/APP1..APP15 and COM metadata segments from a JPEG while keeping image data intact."""
    if not jpeg_bytes.startswith(b"\xff\xd8"):
        return jpeg_bytes
    out = bytearray(b"\xff\xd8")
    i = 2
    n = len(jpeg_bytes)
    while i < n:
        if jpeg_bytes[i] != 0xFF:
            # Unexpected data; keep rest verbatim
            out.extend(jpeg_bytes[i:])
            break
        # Skip fill 0xFF bytes
        while i < n and jpeg_bytes[i] == 0xFF:
            i += 1
        if i >= n:
            break
        marker = jpeg_bytes[i]
        i += 1
        # Start of Scan (SOS) or End of Image (EOI): copy remainder verbatim
        if marker == 0xDA:  # SOS
            out.extend(b"\xff\xda")
            out.extend(jpeg_bytes[i:])
            break
        if marker == 0xD9:  # EOI
            out.extend(b"\xff\xd9")
            break
        # Standalone markers without length (RST0..RST7, TEM)
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            out.extend(bytes([0xFF, marker]))
            continue
        if i + 2 > n:
            break
        seg_len = struct.unpack(">H", jpeg_bytes[i:i + 2])[0]
        seg_end = i + seg_len
        if seg_len < 2 or seg_end > n:
            out.extend(bytes([0xFF, marker]))
            out.extend(jpeg_bytes[i:])
            break
        # Drop APP1..APP15 (0xE1..0xEF, includes EXIF/XMP/IPTC/GPS) and COM (0xFE)
        # Keep APP0 (JFIF, 0xE0) and all frame/quantization/Huffman markers
        if (0xE1 <= marker <= 0xEF) or marker == 0xFE:
            i = seg_end
            continue
        out.extend(bytes([0xFF, marker]))
        out.extend(jpeg_bytes[i:seg_end])
        i = seg_end
    return bytes(out)


def _sips_prop(path: Path, prop: str) -> str:
    res = subprocess.run(
        ["sips", "-g", prop, str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    for line in res.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip() == prop:
                return v.strip()
    return ""


def compress_photo(src_path: Path, max_dim: int = 1280, quality: int = 80) -> tuple[bytes, int, int, str]:
    """Resize and compress a photo for mobile screens, baking orientation and stripping EXIF."""
    if not src_path.is_file():
        raise FileNotFoundError(f"Photo not found: {src_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_out = Path(tmpdir) / "out.jpg"

        if shutil.which("sips"):
            # Convert to JPEG and constrain max dimension
            subprocess.run(
                [
                    "sips",
                    "-s", "format", "jpeg",
                    "-s", "formatOptions", str(quality),
                    "-Z", str(max_dim),
                    str(src_path),
                    "--out", str(tmp_out),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
            )
            # Bake EXIF orientation if still present before stripping EXIF
            orient_str = _sips_prop(tmp_out, "orientation")
            orient = int(orient_str) if orient_str.isdigit() else 1
            if orient == 3:
                subprocess.run(["sips", "-r", "180", str(tmp_out)], stdout=subprocess.DEVNULL, check=True)
            elif orient == 6:
                subprocess.run(["sips", "-r", "90", str(tmp_out)], stdout=subprocess.DEVNULL, check=True)
            elif orient == 8:
                subprocess.run(["sips", "-r", "270", str(tmp_out)], stdout=subprocess.DEVNULL, check=True)
            elif orient == 2:
                subprocess.run(["sips", "-f", "horizontal", str(tmp_out)], stdout=subprocess.DEVNULL, check=True)
            elif orient == 4:
                subprocess.run(["sips", "-f", "vertical", str(tmp_out)], stdout=subprocess.DEVNULL, check=True)

            w_str = _sips_prop(tmp_out, "pixelWidth")
            h_str = _sips_prop(tmp_out, "pixelHeight")
            width = int(w_str) if w_str.isdigit() else 0
            height = int(h_str) if h_str.isdigit() else 0
            raw = strip_jpeg_metadata(tmp_out.read_bytes())
            return raw, width, height, "image/jpeg"

        # Fallback to Pillow if running on Linux/non-macOS
        try:
            from PIL import Image, ImageOps  # type: ignore
            with Image.open(src_path) as im:
                im = ImageOps.exif_transpose(im).convert("RGB")
                im.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)
                width, height = im.size
                im.save(tmp_out, format="JPEG", quality=quality, optimize=True)
            return strip_jpeg_metadata(tmp_out.read_bytes()), width, height, "image/jpeg"
        except ImportError as exc:
            raise RuntimeError(
                "Neither macOS `sips` nor Python `Pillow` is available to compress photos."
            ) from exc


def load_json(path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"Missing required content file: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_date(value: str, label: str) -> None:
    if not isinstance(value, str) or not DATE_RE.match(value):
        raise ValueError(f"Invalid date format for {label}: {value!r} (expected YYYY-MM-DD)")
    dt.date.fromisoformat(value)


def normalize_weeks(weeks_raw: list) -> list:
    normalized = []
    seen = set()
    for idx, entry in enumerate(weeks_raw):
        ws = entry.get("week_start")
        validate_date(ws, f"weeks[{idx}].week_start")
        if ws in seen:
            raise ValueError(f"Duplicate week_start in weeks.json: {ws}")
        seen.add(ws)

        item = {
            "week_start": ws,
            "note": str(entry.get("note", "")).strip(),
        }
        for key in ("sasha", "yulia"):
            p = entry.get(key) or {}
            status = str(p.get("status", "active")).strip().lower()
            if status not in ALLOWED_STATUSES:
                raise ValueError(
                    f"Invalid status {status!r} for {key} on week {ws} "
                    f"(allowed: {sorted(ALLOWED_STATUSES)})"
                )
            activities = [str(a).strip() for a in (p.get("activities") or []) if str(a).strip()]
            if "done" in p and p["done"] is not None:
                done = max(0, int(p["done"]))
            else:
                done = len(activities)
            item[key] = {
                "done": done,
                "status": status,
                "reason": str(p.get("reason", "")).strip(),
                "activities": activities,
            }
        normalized.append(item)
    normalized.sort(key=lambda x: x["week_start"])
    return normalized


def build_bundle(max_dim: int, quality: int) -> tuple[bytes, dict]:
    config = load_json(CONTENT_DIR / "config.json")
    weeks_raw = load_json(CONTENT_DIR / "weeks.json")
    memories_raw = load_json(CONTENT_DIR / "memories.json")

    ch = config.get("challenge") or {}
    validate_date(ch.get("start_date", ""), "config.challenge.start_date")
    validate_date(ch.get("end_date", ""), "config.challenge.end_date")

    weeks = normalize_weeks(weeks_raw)

    photo_blobs = bytearray()
    photo_cache: dict[str, dict] = {}
    orig_photo_bytes = 0
    comp_photo_bytes = 0

    memories = []
    for idx, mem in enumerate(memories_raw):
        date_val = mem.get("date", "")
        validate_date(date_val, f"memories[{idx}].date")
        tag = str(mem.get("tag", "")).strip().lower()
        if tag and tag not in ALLOWED_TAGS:
            print(f"[warn] memories[{idx}] uses custom tag {tag!r} (standard: {sorted(ALLOWED_TAGS)})")

        photos_out = []
        raw_photos = mem.get("photos") or []
        if len(raw_photos) > 3:
            print(f"[warn] memories[{idx}] has {len(raw_photos)} photos (recommended 1-3)")

        for p_entry in raw_photos:
            if isinstance(p_entry, str):
                fname, caption = p_entry, ""
            else:
                fname = str(p_entry.get("file", "")).strip()
                caption = str(p_entry.get("caption", "")).strip()
            if not fname:
                continue

            if fname not in photo_cache:
                src_path = PHOTOS_DIR / fname
                orig_size = src_path.stat().st_size if src_path.is_file() else 0
                raw_bytes, w, h, mime = compress_photo(src_path, max_dim=max_dim, quality=quality)
                offset = len(photo_blobs)
                photo_blobs.extend(raw_bytes)
                orig_photo_bytes += orig_size
                comp_photo_bytes += len(raw_bytes)
                photo_cache[fname] = {
                    "mime": mime,
                    "offset": offset,
                    "length": len(raw_bytes),
                    "width": w,
                    "height": h,
                }

            meta = dict(photo_cache[fname])
            meta["caption"] = caption
            photos_out.append(meta)

        memories.append({
            "id": str(mem.get("id") or f"mem-{date_val}-{idx}"),
            "date": date_val,
            "tag": tag,
            "title": str(mem.get("title", "")).strip(),
            "text": str(mem.get("text", "")).strip(),
            "photos": photos_out,
        })

    # Sort memories newest first (stable on tie)
    memories.sort(key=lambda m: (m["date"], m["id"]), reverse=True)

    payload_obj = {
        "schema": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "config": config,
        "weeks": weeks,
        "memories": memories,
    }
    json_bytes = json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    plaintext = struct.pack(">I", len(json_bytes)) + json_bytes + bytes(photo_blobs)

    stats = {
        "weeks": len(weeks),
        "memories": len(memories),
        "photos": len(photo_cache),
        "orig_photo_bytes": orig_photo_bytes,
        "comp_photo_bytes": comp_photo_bytes,
        "json_bytes": len(json_bytes),
        "plaintext_bytes": len(plaintext),
    }
    return plaintext, stats


def resolve_password(cli_password: str | None) -> str:
    if cli_password:
        return cli_password
    env_pass = os.environ.get("VAULT_PASSWORD", "").strip()
    if env_pass:
        return env_pass
    if PASS_FILE.is_file():
        for line in PASS_FILE.read_text(encoding="utf-8").splitlines():
            pw = line.strip()
            if pw and not pw.startswith("#"):
                return pw
    if not sys.stdin.isatty():
        raise RuntimeError(
            "Password not provided. Set VAULT_PASSWORD, create local `.vault-pass`, or run interactively."
        )
    pw = getpass.getpass("Введите пароль для шифрования vault.enc: ").strip()
    if not pw:
        raise ValueError("Пароль не может быть пустым.")
    return pw


def fmt_kb(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and encrypt docs/vault.enc from local content/")
    parser.add_argument("--password", help="Vault password (prefer .vault-pass or VAULT_PASSWORD)")
    parser.add_argument("--max-dim", type=int, default=1280, help="Max photo dimension in px (default: 1280)")
    parser.add_argument("--quality", type=int, default=80, help="JPEG quality 1-100 (default: 80)")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS, help="PBKDF2 iterations")
    args = parser.parse_args()

    password = resolve_password(args.password)
    plaintext, stats = build_bundle(max_dim=args.max_dim, quality=args.quality)
    sealed = seal_vault(plaintext, password, iterations=args.iterations)

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    tmp_vault = VAULT_PATH.with_suffix(".enc.tmp")
    tmp_vault.write_bytes(sealed)
    os.replace(tmp_vault, VAULT_PATH)

    print("Сборка и шифрование завершены успешно!")
    print(f"  Недель в журнале:  {stats['weeks']}")
    print(f"  Воспоминаний:      {stats['memories']}")
    if stats["photos"] > 0:
        saving = 0.0
        if stats["orig_photo_bytes"] > 0:
            saving = (1.0 - stats["comp_photo_bytes"] / stats["orig_photo_bytes"]) * 100.0
        print(
            f"  Фото ({stats['photos']} шт):      "
            f"{fmt_kb(stats['orig_photo_bytes'])} -> {fmt_kb(stats['comp_photo_bytes'])} "
            f"(сжатие {saving:.0f}%, EXIF удалён)"
        )
    print(f"  Зашифрованный файл: docs/vault.enc ({fmt_kb(len(sealed))}, AES-256-GCM + PBKDF2 {args.iterations:,})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
