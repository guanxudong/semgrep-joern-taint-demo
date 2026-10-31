"""SFTP uploader stub for delivering statements to the custodian."""


def put(host, user, password, account, rows):
    return {"host": host, "user": user, "path": f"/out/{account}.txt", "rows": len(rows)}
