NAME = "Пример: свободное место C:"
def run():
    import shutil
    free = shutil.disk_usage("C:").free / 1e9
    return {"ok": free > 5,
            "text": f"свободно {free:.1f} GB"}
