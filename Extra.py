def capture_file(file_path, platform):
    if not file_path.exists():
        sys.exit(f"{file_path} Not Found.")
    if file_path.is_file():
        if platform == "Singbox" and file_path.suffix != ".json":
            sys.exit(f"Singbox only supports JSON File: {file_path.suffix}")
        return [file_path]
    if file_path.is_dir():
        file = [file for file in file_path.iterdir() if file.is_file()]
        if platform == "Singbox":
            file = [file for file in file if file.suffix == ".json"]
        file = sorted(file)
        if not file:
            print(f"No File Found in: {file_path}")
        return sorted(file)
    sys.exit(f"{file_path} Unknown Type.")
