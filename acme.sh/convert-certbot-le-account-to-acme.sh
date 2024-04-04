#!/bin/sh -eu
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: nil; py-indent-offset: 4 -*-

###  Convert Let's Encrypt account data from certbot to acme.sh
###  Copyright (C) 2024  Matthias "Maddes" Bücher
###
###  This program is free software; you can redistribute it and/or modify
###  it under the terms of the GNU General Public License as published by
###  the Free Software Foundation; either version 2 of the License, or
###  (at your option) any later version.
###
###  This program is distributed in the hope that it will be useful,
###  but WITHOUT ANY WARRANTY; without even the implied warranty of
###  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
###  GNU General Public License for more details.
###
###  You should have received a copy of the GNU General Public License along
###  with this program; if not, write to the Free Software Foundation, Inc.,
###  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
###  Or visit https://www.gnu.org/licenses/old-licenses/gpl-2.0.html.en

PYTHON_VERSION='3' ; ## Use system default of python 3.x
SCRIPT_NAME="$(basename "${0}")"
SCRIPT_PATH="$(dirname "${0}")"

### Check for python module venv
RC=0 ; { "python${PYTHON_VERSION}" -m venv -h >/dev/null ; } || RC="${?}"
if [ "${RC}" -ne 0 ]; then
  printf -- '%s\n' 'Python module "venv" missing. Either install via package manager or pip.'
  return "${RC}" 2>/dev/null || exit "${RC}"
fi

### Check for virtual environment for python version
VENV_PATH="${SCRIPT_PATH}/.venv-${SCRIPT_NAME}-${PYTHON_VERSION}"
if [ ! -d "${VENV_PATH}" ]; then
  printf -- '%s\n' "Initializing Python virtual environment at ${VENV_PATH}"
  RC=0 ; "python${PYTHON_VERSION}" -m venv "${VENV_PATH}" || RC="${?}"
  if [ "${RC}" -ne 0 ]; then
    printf -- '%s\n' "Failed to setup virtual environment in ${VENV_PATH}."
    return "${RC}" 2>/dev/null || exit "${RC}"
  fi
fi

### Activate virtual environment
. "${VENV_PATH}/bin/activate"

### Check for additional python packages in virtual environment
PYTHON_MODULES='josepy cryptography'
for PYTHON_MODULE in ${PYTHON_MODULES}
 do
  RC=0 ; { pip show -q "${PYTHON_MODULE}" 2>/dev/null ; } || RC="${?}"
  if [ "${RC}" -ne 0 ]; then
    printf -- '%s\n' "Installing python module ${PYTHON_MODULE}."
    RC=0 ; python -m pip install "${PYTHON_MODULE}" || RC="${?}"
    if [ "${RC}" -ne 0 ]; then
      printf -- '%s\n' 'Failed.'
      return "${RC}" 2>/dev/null || exit "${RC}"
    fi
  fi
done

SCRIPT_PATH="${0}" python - "${@}" << __EOF
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: nil; py-indent-offset: 4 -*-

## Python 2 future-compatible workarounds: (see: http://python-future.org/compatible_idioms.html)
## a) prevent interpreting print(a,b) as a tuple
from __future__ import print_function
## b) interpret all literals as unicode
from __future__ import unicode_literals

import sys
import argparse
import os
import json
import urllib
## https://josepy.readthedocs.io/
## https://github.com/certbot/josepy
import josepy
import cryptography.hazmat.primitives
import base64


## Define Certbot constants
CERTBOT_DATA = "certbot"
CERTBOT_PRIVATE_KEY_FILE = "private_key.json"
CERTBOT_REGISTRATION_FILE = "regr.json" ## response in "body"
CERTBOT_ACCOUNTS_DIR = "accounts"
REG_CONTENT = "reg_content"

## Define acme.sh constants
ACME_SH_DATA = "acme.sh"
ACME_SH_PRIVATE_KEY_FILE = "account.key"
ACME_SH_ACCOUNT_FILE = "account.json" ## response (not read)
ACME_SH_CA_CONF_FILE = "ca.conf"
ACME_SH_CA_DIR = "ca"

## Define Let's encrypt constants
LE_SERVER_PROD = "acme-v02.api.letsencrypt.org"
LE_SERVER_STAGING = "acme-staging-v02.api.letsencrypt.org"
LE_ACCOUNT_PATH = "/acme/acct"
LE_DIRECTORY_DIR = "directory"

## Define generic constants
KEY_FILENAME = "key_filename"
KEY_CONTENT = "key_content"
ACCOUNT_URL = "account_url"
SERVER_URL = "server_url"


def update_server(server_string):
    if server_string == "acme-v01.api.letsencrypt.org":
        server_string = LE_SERVER_PROD
    elif server_string == "acme-staging.api.letsencrypt.org":
        server_string = LE_SERVER_STAGING

    return server_string


def dir_path(string):
    if os.path.isdir(string):
        return string
    else:
        raise NotADirectoryError(string)


def createArgParser():
    ## argparse: https://docs.python.org/3/library/argparse.html

    ## Create description
    description = "Convert Let's Encrypt account data from certbot to acme.sh\nCopyright (C) 2024  Matthias \"Maddes\" Bücher\nLicensed under GNU GPL v2\n"

    ## Build Arg Parser
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-i", "--indir", metavar="CERTBOT_ACCOUNT_DIR", type=dir_path, required=True, help="Certbot account directory, e.g. /etc/letsencrypt/accounts/<server>/directory/<account>")
    parser.add_argument("-o", "--outdir", metavar="ACME_SH_CA_DIR", type=dir_path, help="acme.sh CA directory, e.g. /root/.acme.sh/config/ca")

    return parser


if __name__ == "__main__":
    sys.argv[0] = os.environ["SCRIPT_PATH"] ## fix script name for argparse output
    ## Check parameters from command line
    Parser = createArgParser()
    Arguments = Parser.parse_args()
    Variables = {}
    Variables[CERTBOT_DATA] = {}
    Variables[ACME_SH_DATA] = {}
    ## Check and process input dir
    if Arguments.indir:
        Arguments.indir = os.path.normpath(Arguments.indir.strip())
    if Arguments.indir:
        ## Check for private_key.json
        Variables[CERTBOT_DATA][KEY_FILENAME] = os.path.join(Arguments.indir, CERTBOT_PRIVATE_KEY_FILE)
        Variables[CERTBOT_DATA][KEY_CONTENT] = None
        if not os.path.exists(Variables[CERTBOT_DATA][KEY_FILENAME]):
            print("ERROR: File does not exist {}".format(Variables[CERTBOT_DATA][KEY_FILENAME]))
        else:
            with open(Variables[CERTBOT_DATA][KEY_FILENAME]) as f:
                Variables[CERTBOT_DATA][KEY_CONTENT] = json.load(f)

        ## Check for regr.json
        Variables[CERTBOT_DATA]["reg_filename"] = os.path.join(Arguments.indir, CERTBOT_REGISTRATION_FILE)
        Variables[CERTBOT_DATA][REG_CONTENT] = None
        Variables[CERTBOT_DATA][ACCOUNT_URL] = None
        Variables[CERTBOT_DATA][SERVER_URL] = None
        if not os.path.exists(Variables[CERTBOT_DATA]["reg_filename"]):
            print("ERROR: File does not exist {}".format(Variables[CERTBOT_DATA]["reg_filename"]))
        else:
            with open(Variables[CERTBOT_DATA]["reg_filename"]) as f:
                Variables[CERTBOT_DATA][REG_CONTENT] = json.load(f)
            if Variables[CERTBOT_DATA][REG_CONTENT] \
            and Variables[CERTBOT_DATA][REG_CONTENT]["uri"]:
                Path_Components = urllib.parse.urlsplit(Variables[CERTBOT_DATA][REG_CONTENT]["uri"])
                Variables[CERTBOT_DATA][SERVER_URL] = Path_Components.netloc
                Path_Components = Path_Components.path.split("/")
                Variables[CERTBOT_DATA][ACCOUNT_URL] = Path_Components[-1]
        #
        if not Variables[CERTBOT_DATA][ACCOUNT_URL]:
            print("ERROR: Could not determine Let's Encrypt account id, result will be incomplete.")
            Variables[CERTBOT_DATA][ACCOUNT_URL] = "<unknown LE id>"
        elif not Variables[CERTBOT_DATA][ACCOUNT_URL].isnumeric():
            print("ERROR: Let's Encrypt id '{}' is not numeric, result will be invalid.".format(Variables[CERTBOT_DATA][ACCOUNT_URL]))
            Variables[CERTBOT_DATA][ACCOUNT_URL] = "".join(("<invalid LE id ", Variables[CERTBOT_DATA][ACCOUNT_URL], ">"))
        ## Update servers
        if not Variables[CERTBOT_DATA][SERVER_URL]:
            print("ERROR: Could not determine Let's Encrypt server, result will be incomplete.")
        else:
            Variables[CERTBOT_DATA][SERVER_URL] = update_server(Variables[CERTBOT_DATA][SERVER_URL])

        ## Check path components (server, account, etc.)
        Path_Count = 0
        Path_Remaining = Arguments.indir
        Variables[CERTBOT_DATA]["count_directory"] = None
        Variables[CERTBOT_DATA]["count_accounts"] = None
        Variables[CERTBOT_DATA]["account_dir"] = None
        Variables[CERTBOT_DATA]["server_dir"] = None
        while Path_Remaining:
            Path_Components = os.path.split(Path_Remaining)
            if not Path_Components[1]:
                break
            Path_Count += 1
            if Path_Components[1] == LE_DIRECTORY_DIR:
                Variables[CERTBOT_DATA]["count_directory"] = Path_Count
                if Path_Count != 2:
                    print("WARN: Path component '{}' is not 2nd to last, but {}".format(LE_DIRECTORY_DIR, Path_Count))
                    break
            elif Path_Components[1] == CERTBOT_ACCOUNTS_DIR:
                Variables[CERTBOT_DATA]["count_accounts"] = Path_Count
                if Path_Count != 4:
                    print("WARN: Path component '{}' is not 4th to last, but {}".format(CERTBOT_ACCOUNTS_DIR, Path_Count))
                    break
            elif Path_Count == 1:
                Variables[CERTBOT_DATA]["account_dir"] = Path_Components[1]
            elif Path_Count == 3:
                Variables[CERTBOT_DATA]["server_dir"] = Path_Components[1]
            else:
                break
            Path_Remaining=Path_Components[0]
        #
        if not Variables[CERTBOT_DATA]["account_dir"] \
        or not Variables[CERTBOT_DATA]["server_dir"] \
        or not Variables[CERTBOT_DATA]["count_directory"] \
        or not Variables[CERTBOT_DATA]["count_accounts"] \
        or Variables[CERTBOT_DATA]["count_directory"] != 2 \
        or Variables[CERTBOT_DATA]["count_accounts"] != 4:
            Variables[CERTBOT_DATA]["is_account_dir"] = False
            Variables[CERTBOT_DATA]["account_dir"] = None
            Variables[CERTBOT_DATA]["server_dir"] = None
            print("WARN: Path '{}' is not a certbot account directory.".format(Arguments.indir))
        else:
            Variables[CERTBOT_DATA]["is_account_dir"] = True
            ## Update servers
            Variables[CERTBOT_DATA]["server_dir"] = update_server(Variables[CERTBOT_DATA]["server_dir"])
            if Variables[CERTBOT_DATA]["server_dir"] \
            and Variables[CERTBOT_DATA][SERVER_URL] \
            and Variables[CERTBOT_DATA]["server_dir"] != Variables[CERTBOT_DATA][SERVER_URL]:
                print("WARN: Path server component '{}' does not match url server '{}', please check final result.".format(Variables[CERTBOT_DATA]["server_dir"], Variables[CERTBOT_DATA][SERVER_URL]))

        ## Copy data to acme.sh variables
        if not Variables[CERTBOT_DATA][SERVER_URL]:
            Variables[CERTBOT_DATA][SERVER_URL] = "<unknown server>"
        #
        Variables[ACME_SH_DATA][SERVER_URL] = Variables[CERTBOT_DATA][SERVER_URL]
        Variables[ACME_SH_DATA][ACCOUNT_URL] = Variables[CERTBOT_DATA][ACCOUNT_URL]
        #
        if Variables[ACME_SH_DATA][SERVER_URL] == LE_SERVER_PROD:
            Variables[ACME_SH_DATA]["server"] = "letsencrypt"
        elif Variables[ACME_SH_DATA][SERVER_URL] == LE_SERVER_STAGING:
            Variables[ACME_SH_DATA]["server"] = "letsencrypt_test"
        else:
            Variables[ACME_SH_DATA]["server"] = "<unknown server>"

    ## Check and process output dir
    if Arguments.outdir:
        Arguments.outdir = os.path.normpath(Arguments.outdir.strip())
    if Arguments.outdir:
        ## Check last path component (ca)
        Path_Components = os.path.split(Arguments.outdir)
        if Path_Components[1] != ACME_SH_CA_DIR:
            print("WARN: Path '{}' is not an acme.sh '{}' directory.".format(Arguments.outdir, ACME_SH_CA_DIR))
            print("WARN: Using directory directly.")
            Variables[ACME_SH_DATA]["is_ca_dir"] = False
            Variables[ACME_SH_DATA]["account_path"] = Arguments.outdir
        else:
            Variables[ACME_SH_DATA]["is_ca_dir"] = True
            ## Check directory
            if Variables[ACME_SH_DATA][SERVER_URL]:
                Variables[ACME_SH_DATA]["account_path"] = os.path.join(Arguments.outdir, Variables[ACME_SH_DATA][SERVER_URL], LE_DIRECTORY_DIR)
            else:
                Variables[ACME_SH_DATA]["account_path"] = os.path.join(Arguments.outdir, "unknown-server", LE_DIRECTORY_DIR)
        ## Define file paths and related variables
        Variables[ACME_SH_DATA][KEY_FILENAME] = os.path.join(Variables[ACME_SH_DATA]["account_path"], ACME_SH_PRIVATE_KEY_FILE)
        Variables[ACME_SH_DATA]["account_file"] = os.path.join(Variables[ACME_SH_DATA]["account_path"], ACME_SH_ACCOUNT_FILE)
        Variables[ACME_SH_DATA]["ca_file"] = os.path.join(Variables[ACME_SH_DATA]["account_path"], ACME_SH_CA_CONF_FILE)
        ## Check for existing files
        if os.path.lexists(Variables[ACME_SH_DATA][KEY_FILENAME]):
            print("ERROR: File '{}' exists. Not overwritng files.".format(Variables[ACME_SH_DATA][KEY_FILENAME]))
            Arguments.outdir = None
        if os.path.lexists(Variables[ACME_SH_DATA]["account_file"]):
            print("ERROR: File '{}' exists. Not overwritng files.".format(Variables[ACME_SH_DATA]["account_file"]))
            Arguments.outdir = None
        if os.path.lexists(Variables[ACME_SH_DATA]["ca_file"]):
            print("ERROR: File '{}' exists. Not overwritng files.".format(Variables[ACME_SH_DATA]["ca_file"]))
            Arguments.outdir = None
    else:
        Variables[ACME_SH_DATA][KEY_FILENAME] = ACME_SH_PRIVATE_KEY_FILE
        Variables[ACME_SH_DATA]["account_file"] = ACME_SH_ACCOUNT_FILE
        Variables[ACME_SH_DATA]["ca_file"] = ACME_SH_CA_CONF_FILE

    ## Create PEM version of private key
    Variables[ACME_SH_DATA][KEY_CONTENT] = None
    Variables[ACME_SH_DATA]["key_file_sha256"] = None
    if Variables[CERTBOT_DATA][KEY_CONTENT]:
        Key = josepy.JWK.json_loads(json.dumps(Variables[CERTBOT_DATA][KEY_CONTENT]))
        #
        Pem = Key.key.private_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM, format=cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption())
        #
        Variables[ACME_SH_DATA][KEY_CONTENT] = Pem.decode('unicode_escape')
        #
        Digest = cryptography.hazmat.primitives.hashes.Hash(cryptography.hazmat.primitives.hashes.SHA256())
        Digest.update(Pem)
        Hash = Digest.finalize()
        Variables[ACME_SH_DATA]["key_file_sha256"] = base64.standard_b64encode(Hash).decode('unicode_escape')

    ## Copy response data (not necessary but may be of interest)
    Variables[ACME_SH_DATA]["account_content"] = {}
    if Variables[CERTBOT_DATA][REG_CONTENT] \
    and Variables[CERTBOT_DATA][REG_CONTENT]["body"]:
        if Variables[CERTBOT_DATA][REG_CONTENT]["body"]["key"]:
            Variables[ACME_SH_DATA]["account_content"]["key"] = Variables[CERTBOT_DATA][REG_CONTENT]["body"]["key"]
        if Variables[CERTBOT_DATA][REG_CONTENT]["body"]["contact"]:
            Variables[ACME_SH_DATA]["account_content"]["contact"] = Variables[CERTBOT_DATA][REG_CONTENT]["body"]["contact"]

    ## Copy CA configuration
    Variables[ACME_SH_DATA]["ca_content"] = ""
    ## a) e-mail if available
    Variables[ACME_SH_DATA]["ca_content"] += "CA_EMAIL='"
    if Variables[CERTBOT_DATA][REG_CONTENT] \
    and Variables[CERTBOT_DATA][REG_CONTENT]["body"] \
    and Variables[CERTBOT_DATA][REG_CONTENT]["body"]["contact"] \
    and Variables[CERTBOT_DATA][REG_CONTENT]["body"]["contact"][0]:
        Path_Components = urllib.parse.urlsplit(Variables[CERTBOT_DATA][REG_CONTENT]["body"]["contact"][0])
        Variables[ACME_SH_DATA]["ca_content"] += Path_Components.path
    Variables[ACME_SH_DATA]["ca_content"] += "'\n"
    ## b) acccount url
    Variables[ACME_SH_DATA]["ca_content"] += "ACCOUNT_URL='"
    Path_Components = urllib.parse.SplitResult("https", Variables[ACME_SH_DATA][SERVER_URL], "/".join((LE_ACCOUNT_PATH, Variables[ACME_SH_DATA][ACCOUNT_URL])), "", "")
    Variables[ACME_SH_DATA]["ca_content"] += urllib.parse.urlunsplit(Path_Components)
    Variables[ACME_SH_DATA]["ca_content"] += "'\n"
    ## c) sha256 of key
    Variables[ACME_SH_DATA]["ca_content"] += "CA_KEY_HASH='"
    Variables[ACME_SH_DATA]["ca_content"] += Variables[ACME_SH_DATA]["key_file_sha256"]
    Variables[ACME_SH_DATA]["ca_content"] += "'\n"

    print(json.dumps(Variables, indent=2))

    ## Write files
    if Arguments.outdir:
        if Variables[ACME_SH_DATA][KEY_FILENAME] \
        and Variables[ACME_SH_DATA][KEY_CONTENT]:
            print("INFO: Writing '{}'".format(Variables[ACME_SH_DATA][KEY_FILENAME]))
            os.makedirs(os.path.dirname(Variables[ACME_SH_DATA][KEY_FILENAME]), exist_ok=True)
            with open(Variables[ACME_SH_DATA][KEY_FILENAME], "w") as f:
                f.write(Variables[ACME_SH_DATA][KEY_CONTENT])
        #
        if Variables[ACME_SH_DATA]["ca_file"]:
            print("INFO: Writing '{}'".format(Variables[ACME_SH_DATA]["ca_file"]))
            os.makedirs(os.path.dirname(Variables[ACME_SH_DATA]["ca_file"]), exist_ok=True)
            with open(Variables[ACME_SH_DATA]["ca_file"], "w") as f:
                f.write(Variables[ACME_SH_DATA]["ca_content"])
        #
        if Variables[ACME_SH_DATA]["account_file"]:
            print("INFO: Writing '{}'".format(Variables[ACME_SH_DATA]["account_file"]))
            os.makedirs(os.path.dirname(Variables[ACME_SH_DATA]["account_file"]), exist_ok=True)
            with open(Variables[ACME_SH_DATA]["account_file"], "w") as f:
                json.dump(Variables[ACME_SH_DATA]["account_content"], f, indent=2)

        print("Check result, if fine and also no errors listed above, then try to update account with acme.sh.")
        print("command: acme.sh --update-account --server {} ; # optional -m <email>".format(Variables[ACME_SH_DATA]["server"]))

    sys.exit(0)
__EOF
