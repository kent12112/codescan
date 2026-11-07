SECRET = "top"
def admin(headers):
    if headers.get("X-Admin") == "true":                     # broken access control
        return SECRET
    return "forbidden"
