"""把图标文件规整成 PyInstaller 能直接用的 .ico。

build_exe.bat 会调用它：
    python tools/prepare_icon.py myicon.ico build/app.ico      # 已经是 ICO -> 直接复用
    python tools/prepare_icon.py logo.png    build/app.ico     # PNG/JPG -> 转成多尺寸 ICO

为什么要这么绕：
- PyInstaller 的 icon 参数只认 .ico（Windows 资源），喂 PNG 会直接报错；
- 网上随手下的 ico 经常只有 256x256 一帧，任务栏/资源管理器里显示成白块；
- 图标长宽比不是 1:1 时直接缩放会被拉扁，所以先补透明边车成正方形再压。

依赖：转换分支需要 Pillow（pip install pillow）；ICO 分支纯标准库。
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (72, 72), (96, 96), (128, 128), (256, 256)]
ICO_HEADER = (0, 0, 1, 0)  # reserved=0, type=1(icon)


def is_ico(path: Path) -> bool:
    """只看 6 字节头：reserved=0, type=1, count>0。比按扩展名判断靠谱。"""
    try:
        head = path.read_bytes()[:6]
    except OSError:
        return False
    if len(head) != 6:
        return False
    return tuple(head[:4]) == ICO_HEADER and (head[4] + head[5]) > 0


def ico_sizes(path: Path) -> list[tuple[int, int]]:
    """读 ICO 目录里每一帧的宽高（0 表示 256）。"""
    data = path.read_bytes()
    count = int.from_bytes(data[4:6], "little")
    sizes: list[tuple[int, int]] = []
    for index in range(count):
        offset = 6 + index * 16
        if offset + 2 > len(data):
            break
        width = data[offset] or 256
        height = data[offset + 1] or 256
        sizes.append((width, height))
    return sizes


def convert(src: Path, dst: Path) -> list[tuple[int, int]]:
    try:
        from PIL import Image
    except ImportError as exc:  # pragma: no cover - 只在缺依赖时触发
        raise SystemExit(
            f"错误：{src.name} 不是 .ico，转成 ICO 需要 Pillow。\n"
            f"      pip install pillow 之后再跑，或者直接把 ico 文件传进来。"
        ) from exc

    image = Image.open(src).convert("RGBA")
    side = max(image.size)
    # 非正方形图片补透明边，避免被拉扁
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.paste(image, ((side - image.width) // 2, (side - image.height) // 2))
    dst.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(dst, format="ICO", sizes=SIZES)
    return ico_sizes(dst)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: python tools/prepare_icon.py <source-icon> <output.ico>", file=sys.stderr)
        return 2

    src, dst = Path(argv[1]), Path(argv[2])
    if not src.is_file():
        print(f"ERROR: icon not found: {src}", file=sys.stderr)
        return 1
    dst.parent.mkdir(parents=True, exist_ok=True)

    if is_ico(src):
        if src.resolve() != dst.resolve():
            shutil.copyfile(src, dst)
        sizes = ico_sizes(dst)
        print(f"      already a valid ICO, reuse as-is: {len(sizes)} frames {sizes}")
    else:
        print(f"      {src.name} is not an ICO, converting to multi-size ICO ...")
        sizes = convert(src, dst)
        print(f"      generated {len(sizes)} frames {sizes}")

    missing = [(w, h) for (w, h) in SIZES if (w, h) not in sizes]
    if missing:
        print(f"      WARN missing sizes {missing}, small icons may look blurry (build still works)")
    print(dst.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
