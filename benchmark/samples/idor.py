ACCOUNTS = {"1": {"ssn": "aaa"}, "2": {"ssn": "bbb"}}
def account(current_user, acct_id):
    return ACCOUNTS.get(acct_id)                             # IDOR: no ownership check
