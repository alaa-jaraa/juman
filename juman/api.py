import json

import frappe
import frappe.utils
from frappe.utils.oauth import login_via_oauth2, login_via_oauth2_id_token
import json
from urllib.parse import quote, urlencode

from oauthlib.oauth2 import FatalClientError, OAuth2Error
from oauthlib.openid.connect.core.endpoints.pre_configured import Server as WebApplicationServer

import frappe
from frappe.integrations.doctype.oauth_provider_settings.oauth_provider_settings import (
	get_oauth_settings,
)
from frappe.oauth import (
	OAuthWebRequestValidator,
	generate_json_error_response,
	get_server_url,
	get_userinfo,
)
from frappe.integrations.oauth2 import (
	encode_params,
    sanitize_kwargs,
    get_oauth_server
)
@frappe.whitelist(allow_guest=True)
def login_via_frappe(code: str, state: str):
    print("///////////////////////////////////////////////")
    print("Login via Frappe called with code and state:")
    print(code, state)
    # frappe.log_error(code, state)
    login_via_oauth2("frappe", code, state, decoder=decoder_compat)


# @frappe.whitelist(allow_guest=True)
# def authorize(**kwargs):
# 	success_url = "/api/method/frappe.integrations.oauth2.approve?" + encode_params(sanitize_kwargs(kwargs))
# 	failure_url = frappe.form_dict["redirect_uri"] + "?error=access_denied"

# 	if frappe.session.user == "Guest":
# 		# Force login, redirect to preauth again.
# 		frappe.local.response["type"] = "redirect"
# 		frappe.local.response["location"] = "/login?" + encode_params({"redirect-to": frappe.request.url})
# 	else:
# 		try:
# 			r = frappe.request
# 			(
# 				scopes,
# 				frappe.flags.oauth_credentials,
# 			) = get_oauth_server().validate_authorization_request(r.url, r.method, r.get_data(), r.headers)

# 			skip_auth = frappe.db.get_value(
# 				"OAuth Client",
# 				frappe.flags.oauth_credentials["client_id"],
# 				"skip_authorization",
# 			)
# 			unrevoked_tokens = frappe.get_all("OAuth Bearer Token", filters={"status": "Active"})

# 			if skip_auth or (get_oauth_settings().skip_authorization == "Auto" and unrevoked_tokens):
# 				frappe.local.response["type"] = "redirect"
# 				frappe.local.response["location"] = success_url
# 			else:
# 				if "openid" in scopes:
# 					scopes.remove("openid")
# 					scopes.extend(["Full Name", "Email", "User Image", "Roles"])

# 				# Show Allow/Deny screen.
# 				response_html_params = frappe._dict(
# 					{
# 						"client_id": frappe.db.get_value("OAuth Client", kwargs["client_id"], "app_name"),
# 						"success_url": success_url,
# 						"failure_url": failure_url,
# 						"details": scopes,
# 					}
# 				)
# 				resp_html = frappe.render_template(
# 					"templates/includes/oauth_confirmation.html", response_html_params
# 				)
# 				frappe.respond_as_web_page(frappe._("Confirm Access"), resp_html, primary_action=None)
# 			print("///////////////////////////////////////////////")
# 			print("Login via Frappe called with code and state:")
# 			redirect_uri = kwargs.get('redirect_uri')
# 			print(r)
# 			import urllib.parse
# 			if redirect_uri:
# 				# Parse the URL to get its components
# 				parsed_url = urllib.parse.urlparse(redirect_uri)
# 				# The domain is in the 'netloc' component of the parsed URL
# 				domain = parsed_url.netloc
# 				print(f"The new domain being redirected to is: {domain}")
# 			print(frappe.session.user)
# 		except (FatalClientError, OAuth2Error) as e:
# 			return generate_json_error_response(e)


@frappe.whitelist(allow_guest=True)
def authorize(**kwargs):
    success_url = "/api/method/frappe.integrations.oauth2.approve?" + encode_params(sanitize_kwargs(kwargs))
    failure_url = frappe.form_dict["redirect_uri"] + "?error=access_denied"

    if frappe.session.user == "Guest":
        # Force login, redirect to preauth again.
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = "/login?" + encode_params({"redirect-to": frappe.request.url})
    else:
        try:
            r = frappe.request
            (
                scopes,
                frappe.flags.oauth_credentials,
            ) = get_oauth_server().validate_authorization_request(r.url, r.method, r.get_data(), r.headers)

            skip_auth = frappe.db.get_value(
                "OAuth Client",
                frappe.flags.oauth_credentials["client_id"],
                "skip_authorization",
            )
            unrevoked_tokens = frappe.get_all("OAuth Bearer Token", filters={"status": "Active"})

            if skip_auth or (get_oauth_settings().skip_authorization == "Auto" and unrevoked_tokens):
                frappe.local.response["type"] = "redirect"
                frappe.local.response["location"] = success_url
            else:
                if "openid" in scopes:
                    scopes.remove("openid")
                    scopes.extend(["Full Name", "Email", "User Image", "Roles"])

                # Show Allow/Deny screen.
                response_html_params = frappe._dict(
                    {
                        "client_id": frappe.db.get_value("OAuth Client", kwargs["client_id"], "app_name"),
                        "success_url": success_url,
                        "failure_url": failure_url,
                        "details": scopes,
                    }
                )
                resp_html = frappe.render_template(
                    "templates/includes/oauth_confirmation.html", response_html_params
                )
                frappe.respond_as_web_page(frappe._("Confirm Access"), resp_html, primary_action=None)

            # Your new logic starts here
            user = frappe.session.user
            redirect_uri = kwargs.get('redirect_uri')

            if redirect_uri and user != "Guest":
                import urllib.parse
                parsed_url = urllib.parse.urlparse(redirect_uri)
                domain_name = parsed_url.netloc

                # Check and create Websites record if it doesn't exist
                website_doc_name = frappe.db.get_value("Websites", {"domain": domain_name}, "name")
                if not website_doc_name:
                    website_doc = frappe.new_doc("Websites")
                    website_doc.website_name = domain_name
                    website_doc.domain = domain_name
                    website_doc.insert(ignore_permissions=True)
                    website_doc_name = website_doc.name
                    frappe.db.commit()
                print("///////////////////////////////////////////////")
                print(f"The website_doc_name is: {website_doc_name}")
                # Check and create Websites Users record if it doesn't exist
                website_user_exists = frappe.db.exists(
                    "Websites Users",
                    {
                        "user": user,
                        "website": website_doc_name
                    }
                )

                if not website_user_exists:
                    website_user_doc = frappe.new_doc("Websites Users")
                    website_user_doc.user = user
                    website_user_doc.website = website_doc_name
                    website_user_doc.insert(ignore_permissions=True)
                    frappe.db.commit()
                print("///////////////////////////////////////////////")
        except (FatalClientError, OAuth2Error) as e:
            return generate_json_error_response(e)