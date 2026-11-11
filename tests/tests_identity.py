from types import SimpleNamespace


def identity(role):
    return {'gunicorn.socket':SimpleNamespace(getpeercert=lambda:{'subjectAltName':[('URI','spiffe://codescan.local/'+role)]})}
