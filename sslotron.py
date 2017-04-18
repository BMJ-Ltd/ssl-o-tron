#!/usr/bin/env python3

from __future__ import print_function

from configparser import ConfigParser
from OpenSSL import crypto

import boto3
import tempfile
import yaml
import os
import datetime
import logging
import subprocess
import acme
import tarfile
import requests
import json



# ==========================================
#   Logging
# ------------------------------------------
# Create log object
log = logging.getLogger('sslotron_logger')
log.setLevel(logging.INFO)

# Stream and file handlers
stream_handler = logging.StreamHandler()

if os.access("/var/log/sslotron.log", os.W_OK):
    file_handler = logging.FileHandler("/var/log/sslotron.log")
else:
    file_handler = logging.FileHandler("/tmp/sslotron.log")

# Add formatting
formatter = logging.Formatter('%(asctime)s [%(name)s] %(levelname)s %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

# Add handlers to logger
log.addHandler(stream_handler)
log.addHandler(file_handler)



# ==========================================
#   Functions
# ------------------------------------------
# helper function to run openssl command
def _openssl(command, options, communicate=None):
    openssl = subprocess.Popen(["openssl", command] + options,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = openssl.communicate(communicate)
    if openssl.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    return out



def run(command, options, communicate=None, env=None):
    appl = subprocess.Popen([command] + options,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    out, err = appl.communicate(communicate)
    if appl.returncode != 0:
        raise IOError("Subprocess Error: {0}".format(err))
    return out



# Given a file and an RSA encryption strength, this function writes a private key
def write_key_file(keyfile, rsa):
    log.info("Generating " + keyfile + " ...")

    with open(keyfile, "wb") as kf:
        kf.write(_openssl("genrsa", [rsa]))



# Use the openssl command to return the date a certificate expires
def ssl_expires(domain):
    try:
        ssl_info = {}

        out, err = subprocess.Popen("echo | openssl s_client -connect " + domain + ":443 | openssl x509 -noout -dates",
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()

        # 'out' will look like this:
        #    b'notBefore=Mar 16 09:13:00 2017 GMT\nnotAfter=Jun 14 09:13:00 2017 GMT\n'

        # Split along newlines first, then =, to get notBefore and notAfter into a dictionary
        for x in out.decode().splitlines():
            ssl_info[x.split('=')[0]] = x.split('=')[1]

        return datetime.datetime.strptime(ssl_info['notAfter'], r'%b %d %H:%M:%S %Y %Z')
    except:
        return False



# Get the days left before a certificate expires
def days_to_go(domain):
    expiry = ssl_expires(domain)

    if expiry:
        return expiry - datetime.datetime.now()
    else:
        return expiry



# Check if domains expires within window
def renew_soon(domains, window):

    renew = False

    for d in domains:   
        time_left = days_to_go(d)

        if time_left:
            log.info(d + " expires in " + str(time_left.days) + " days")

            if time_left.days <= window.days:
                renew = time_left

    return renew


# Build the OpenSSL friendly list of SANS
def get_sans(domains):
    sans = []
    for number, domain in enumerate(domains, start=1):
        sans.append("DNS:{0}".format(domain))
    return sans


# Returns a CSR
def gen_csr(sans, domainkeyfile):
    log.info("Generating CSR...")
    request = crypto.X509Req()
    request.add_extensions([
        crypto.X509Extension(b"keyUsage", False, b"Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(b"subjectAltName", False, (",".join(sans)).encode("utf-8"))
    ])
    with open(domainkeyfile) as keyfile:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, keyfile.read())
        request.set_pubkey(key)
        request.sign(key, "sha256")

    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, request)

    return csr


# Returns the path to a tar.gz archive containing the certificate and key file
def get_cert_tar(outputfile, domains, rsa):

    csrname = domains[0] + ".csr"
    crtname = domains[0] + ".crt"
    keyname = domains[0] + ".key"

    with tempfile.TemporaryDirectory() as tempdir:

        sans = get_sans(domains)

        if rsa == "4096":
            config["acmednstiny"]["DomainKeyFile"] = key4096
        else:
            config["acmednstiny"]["DomainKeyFile"] = key2048

        domainkeyfile = os.path.abspath(config.get("acmednstiny", "DomainKeyFile"))

        log.info("Creating certificate for {0}".format(" ".join(domains)))

        csr = gen_csr(sans, domainkeyfile)

        # Write CSR to file
        with open(os.path.join(tempdir, csrname), "wb") as csrfile:
            csrfile.write(csr)

        # Run the certificate generation
        config["acmednstiny"]["CSRFile"] = os.path.join(tempdir, csrname)
        crt = acme.get_crt(config, log=log)

        # Write certificate to file
        log.info("Writing certificate to file...")
        with open(os.path.join(tempdir, crtname), "w") as crtfile:
            crtfile.write(crt)

        # Now delete the CSR, as we're finished with it
        os.remove(os.path.join(tempdir, csrname))

        # tar up the key and cert into a certificate package
        log.info("Creating certificate package...")
        tar = tarfile.open(outputfile, mode="w:gz")
        try:
            log.info("Adding private key to archive")
            tar.add(domainkeyfile, arcname=keyname)
            log.info("Adding certificate to archive")
            tar.add(os.path.join(tempdir, crtname), arcname=crtname)
        finally:
            tar.close()
        os.remove(os.path.join(tempdir, crtname))

        return outputfile


# Send a slack notification via an Incoming WebHook, formatted as a message attachment
def slack(webhook_url, domains, time_left, certificate_url):

    domain_list = ", ".join(domains)

    p = {
        "attachments": [
            {
                "fallback": "The certificate for " + domains[0] + " expires soon. Link: " + certificate_url,
                "title": "Certificate for " + domains[0] + " expires soon!",
                "title_link": certificate_url,
                "text": "Click the link in the title to download the new certificate and private key.",
                "fields": [
                    {
                        "title": "Domains",
                        "value": domain_list,
                        "short": True
                    },
                    {
                        "title": "Days until expiry",
                        "value": time_left,
                        "short": True
                    }
                ]
            }
        ]
    }

    r = requests.post(webhook_url, data=json.dumps(p))

    if r.status_code == 200:
        log.info("Sending slack notification...\n" + str(r.status_code) + " " + r.text)
    else:
        log.error("Sending slack notification...\n" + str(r.status_code) + " " + r.text)


# Change path to the path of the script
os.chdir(os.path.dirname(os.path.abspath(__file__)))



# ==========================================
#   Read config
# ------------------------------------------
configfilepath = os.path.abspath("config/config.ini")

config = ConfigParser(allow_no_value=True)
config.read_dict({
    "acmednstiny": {
        "CAUrl": "https://acme-staging.api.letsencrypt.org",
        "CheckChallengeDelay": 5,
    },
    "DNS": {"Port": "53"}
})
config.read(configfilepath)

if (set(["accountkeyfile", "caurl", "checkchallengedelay"]) - set(config.options("acmednstiny"))):
    raise ValueError("Some required settings are missing.")



# ==========================================
#   Private keys
# ------------------------------------------
accountkeyfile   = os.path.abspath(config.get("acmednstiny", "AccountKeyFile"))
certificatesfile = os.path.abspath(config.get("acmednstiny", "CertificatesListFile"))
key2048          = os.path.abspath(config.get("keys", "key2048"))
key4096          = os.path.abspath(config.get("keys", "key4096"))

if not os.path.isfile(accountkeyfile):
    write_key_file(accountkeyfile, "4096")
else:
    log.info("Account key found. Continuing...")

if not os.path.isfile(key2048):
    write_key_file(key2048, "2048")
else:
    log.info("RSA-2048 private key found. Continuing...")

if not os.path.isfile(key4096):
    write_key_file(key4096, "4096")
else:
    log.info("RSA-4096 private key found. Continuing...")