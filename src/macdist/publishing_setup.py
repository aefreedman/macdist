"""Configure only publishing secret references; never retrieve or store raw secrets."""

import re
import sys

from .engine import DistributionError
from .setup import save_profile
from .publish import TOKEN_ENV


def setup_publishing(args):
    values = {"profile": args.profile, "api_key_ref": args.api_key_ref,
              "keychain_service": args.keychain_service, "keychain_account": args.keychain_account}
    prompts = {"profile": "Local publishing profile name: ",
               "api_key_ref": "Butler API key reference (op://vault/item/field): ",
               "keychain_service": "Keychain service containing publishing service-account token: ",
               "keychain_account": "Keychain account: "}
    for key, value in values.items():
        if not value:
            if not sys.stdin.isatty():
                raise DistributionError("Noninteractive setup-publishing requires all profile/reference/Keychain fields.")
            values[key] = input(prompts[key]).strip()
    name = values.pop("profile")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise DistributionError("Profile name may contain only letters, digits, underscores and hyphens.")
    values["token_env"] = args.token_env or TOKEN_ENV
    save_profile(args.user_config.expanduser().absolute(), name, values, args.replace_profile, group="publishing_profiles")
    print(f"Saved nonsecret publishing profile {name!r} to {args.user_config}.")
    print("No credentials were accessed or validated. In Keychain Access, create a generic password item:")
    print(f"  Item name/service: {values['keychain_service']}\n  Account: {values['keychain_account']}")
    print("  Password: your dedicated read-only 1Password publishing service-account token.")
    print(f"For CI, supply the raw token through {values['token_env']} from the CI secret store.")
    print("Scope that service account to the publishing vault only. Never put the raw token in command arguments or source control.")
    return 0
