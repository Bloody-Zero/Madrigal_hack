"""Cross-platform source launcher; no system-wide installs at app startup."""
import argparse
import threading
import time
import webbrowser
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description='Лаборатория протоколов')
    parser.add_argument('--project',help='Каталог проекта; создаётся при отсутствии')
    parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--no-browser',action='store_true')
    args=parser.parse_args()
    if not args.project:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root=tk.Tk(); root.withdraw()
            args.project=filedialog.askdirectory(title='Выберите папку исследования')
            root.destroy()
        except Exception:
            args.project=str(Path.cwd()/'research-project')
        if not args.project:
            return
    from lab.capture import version
    from lab.app import create_app
    import uvicorn
    print(version())
    app=create_app(args.project)
    url=f'http://127.0.0.1:{args.port}'
    print(f'Проект: {Path(args.project).resolve()}\nИнтерфейс: {url}\nОстановка: Ctrl+C')
    if not args.no_browser:
        def open_when_ready():
            import urllib.request
            for _ in range(50):
                try:
                    with urllib.request.urlopen(url,timeout=.2):
                        webbrowser.open(url)
                        return
                except OSError:
                    time.sleep(.1)
        threading.Thread(target=open_when_ready,daemon=True).start()
    uvicorn.run(app,host='127.0.0.1',port=args.port,access_log=False)


if __name__=='__main__':
    main()
