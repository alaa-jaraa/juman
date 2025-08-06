import json

import frappe
import frappe.utils
from frappe.utils.oauth import login_via_oauth2, login_via_oauth2_id_token

@frappe.whitelist(allow_guest=True)
def login_via_frappe(code: str, state: str):
    // insert code to handle login via Frappe OAuth2
    print("Login via Frappe called with code and state:")
    print(code, state)
    # frappe.log_error(code, state)
	login_via_oauth2("frappe", code, state, decoder=decoder_compat)