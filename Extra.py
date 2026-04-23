def capture_file(file_path, platform):
    if not file_path.exists():
        sys.exit(f"{file_path} Not Found.")
    if file_path.is_file():
        if platform == "Singbox" and file_path.suffix != ".json":
            sys.exit(f"Singbox only supports JSON File: {file_path.suffix}")
        return [file_path]
    if file_path.is_dir():
        files = [f for f in file_path.iterdir() if f.is_file()]
        if platform == "Singbox":
            files = [f for f in files if f.suffix == ".json"]
        files = sorted(files)
        if not files:
            sys.exit(f"No File Found in Directory: {file_path}")
        return files
    sys.exit(f"{file_path} Unknown Type.")
