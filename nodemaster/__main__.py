import argparse
import asyncio
import os
import re
import secrets
import socket
import webbrowser
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from time import monotonic, sleep

import uvicorn
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"


class InstanceRunning(RuntimeError):
    pass


@contextmanager
def instance_lock(directory: Path) -> Iterator[None]:
    # Keep the lock file; replacing it risks locking two different files.
    with (directory / ".instance.lock").open("a+b") as handle:
        handle.seek(0)
        try:
            if os.name == "nt":
                from msvcrt import LK_NBLCK, locking
                locking(handle.fileno(), LK_NBLCK, 1)
            else:
                from fcntl import LOCK_EX, LOCK_NB, flock
                flock(handle, LOCK_EX | LOCK_NB)
        except OSError as exc:
            raise InstanceRunning from exc
        yield


def available_port(start: int) -> int:
    if not 1 <= start <= 65535:
        raise ValueError("NODEMASTER_PORT 需要为 1–65535")
    for port in range(start, min(start + 50, 65536)):
        with socket.socket() as sock:
            try:
                sock.bind((HOST, port))
                return port
            except OSError:
                continue
    raise RuntimeError("本机没有可用端口")


def read_instance(directory: Path) -> str:
    try:
        return (directory / ".instance").read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return ""


def stop(directory: Path) -> int:
    if directory.is_dir():
        try:
            with instance_lock(directory):
                pass
        except InstanceRunning:
            token = read_instance(directory)
            if not re.fullmatch(r"[0-9a-f]{32}", token):
                print("NodeMaster 正在启动，请稍后重试。", flush=True)
                return 1
            signal = directory / f".stop-{token}"
            signal.touch()
            deadline = monotonic() + 15
            while read_instance(directory) == token and monotonic() < deadline:
                sleep(0.2)
            if read_instance(directory) == token:
                print("已请求停止，服务仍在关闭中。请在原运行窗口查看进度。", flush=True)
                return 1
            signal.unlink(missing_ok=True)
            print("NodeMaster 已停止。", flush=True)
            return 0
    print("此数据目录没有正在运行的 NodeMaster。", flush=True)
    return 0


async def serve(directory: Path, signal: Path) -> None:
    from .api import create_app

    port = available_port(int(os.environ.get("NODEMASTER_PORT", "8765")))
    os.environ["NODEMASTER_PORT"] = str(port)
    server = uvicorn.Server(uvicorn.Config(create_app(directory), host=HOST, port=port,
                                          proxy_headers=False, access_log=False))
    url = f"http://{HOST}:{port}"
    print(f"NodeMaster 本机地址: {url}\n本地数据目录: {directory}", flush=True)

    async def watch() -> None:
        open_page = os.environ.get("NODEMASTER_OPEN_BROWSER", "1") == "1"
        while not server.should_exit:
            if signal.exists():
                server.should_exit = True
                return
            if open_page and server.started:
                open_page = False
                with suppress(OSError, webbrowser.Error):
                    await asyncio.to_thread(webbrowser.open, url)
            await asyncio.sleep(0.2)

    watcher = asyncio.create_task(watch())
    try:
        await server.serve()
    finally:
        watcher.cancel()
        with suppress(asyncio.CancelledError):
            await watcher


def main() -> int:
    parser = argparse.ArgumentParser(description="NodeMaster 本机应用")
    parser.add_argument("--stop", action="store_true", help="停止同一数据目录中正在运行的实例")
    args = parser.parse_args()
    load_dotenv(ROOT / ".env", override=False)
    directory = (ROOT / os.environ.get("NODEMASTER_DATA_DIR", "runtime")).resolve()
    if args.stop:
        return stop(directory)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        with instance_lock(directory):
            token = secrets.token_hex(16)
            state = directory / ".instance"
            pending = directory / ".instance.tmp"
            pending.write_text(token, encoding="ascii")
            pending.replace(state)
            signal = directory / f".stop-{token}"
            try:
                asyncio.run(serve(directory, signal))
            except KeyboardInterrupt:
                pass
            finally:
                state.unlink(missing_ok=True)
                signal.unlink(missing_ok=True)
    except InstanceRunning:
        print("此数据目录已有正在运行的 NodeMaster。", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
