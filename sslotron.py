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

log = logging.getLogger('sslotron_logger')
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

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

def autorenew():
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

    today = datetime.date.today()
    datestamp = today.strftime("%Y%m%d")

    s3bucket = config.get("aws", "s3_bucket")
    accountkeyfile = os.path.abspath(config.get("acmednstiny", "AccountKeyFile"))
    domainkeyfile = os.path.abspath(config.get("acmednstiny", "DomainKeyFile"))
    certificatesfile = os.path.abspath(config.get("acmednstiny", "CertificatesListFile"))

    try:
        boto_settings = {
            "aws_access_key_id": config.get("aws", "aws_access_key_id"),
            "aws_secret_access_key": config.get("aws", "aws_secret_access_key"),
            "region_name": config.get("aws", "aws_region")
        }
    except:
        boto_settings = {
            "region_name": config.get("aws", "aws_region")
        }

    s3 = boto3.client("s3", **boto_settings)
    ses = boto3.client("ses", **boto_settings)

    if not os.path.isfile(accountkeyfile):
        log.info("Generating account key...")
        with open(accountkeyfile, "wb") as keyfile:
            keyfile.write(_openssl("genrsa", ["4096"]))
    else:
        log.info("Account key found. Continuing...")

    if not os.path.isfile(domainkeyfile):
        log.info("Generating domain key...")
        with open(domainkeyfile, "wb") as keyfile:
            keyfile.write(_openssl("genrsa", ["4096"]))
    else:
        log.info("Domain key found. Continuing...")

    with tempfile.TemporaryDirectory() as tempdir:
        with open(certificatesfile) as yamlfile:
            # Load YAML file
            yaml_documents = yaml.safe_load_all(yamlfile)

            for document in yaml_documents:
                # Convert YAML into nicer variables
                # domains, day, emails, from_address, subject, template
                if type(document.get("domains")) is str:
                    domains = [document.get("domains")]
                else:
                    domains = document.get("domains")

                renewal = document.get("day")

                if type(document.get("emails")) is str:
                    emails = [document.get("emails")]
                else:
                    emails = document.get("domains")

                from_address = document.get("from", "operations@bmj.com")
                subject = document.get("subject", "Update certificate")
                template = document.get("template", "default.tmpl")

                # Build the OpenSSL friendly list of SANS
                sans = []
                for number, domain in enumerate(domains, start=1):
                    sans.append("DNS:{0}".format(domain))

                # If today is renewal day, go ahead
                if today.day == int(renewal):
                    log.info("Creating certificate for {0}".format(" ".join(domains)))

                    # Generate CSR
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

                    # Write CSR to file
                    with open(os.path.join(tempdir, "domain.csr"), "wb") as csrfile:
                        csrfile.write(csr)

                    # Run the certificate generation
                    config["acmednstiny"]["CSRFile"] = os.path.join(tempdir, "domain.csr")
                    crt = acme.get_crt(config, log=log)

                    # Write certificate to file
                    log.info("Writing certificate to file...")
                    with open(os.path.join(tempdir, "domain.crt"), "w") as crtfile:
                        crtfile.write(crt)

                    # Now delete the CSR, as we're finished with it
                    os.remove(os.path.join(tempdir, "domain.csr"))

                    # tar up the key and cert into a certificate package
                    log.info("Creating certificate package...")
                    tar = tarfile.open(os.path.join(tempdir, domains[0] + ".tar.gz"), mode="w:gz")
                    try:
                        log.info("Adding private key to archive")
                        tar.add(domainkeyfile, arcname="domain.key")
                        log.info("Adding certificate to archive")
                        tar.add(os.path.join(tempdir, "domain.crt"), arcname="domain.crt")
                    finally:
                        tar.close()

                    os.remove(os.path.join(tempdir, "domain.crt"))

                    # Upload the certificate package to Amazon S3
                    log.info("Uploading certificate to Amazon S3...")
                    s3.upload_file(os.path.join(tempdir, domains[0] + ".tar.gz"), s3bucket, domains[0] + "_" + datestamp + ".tar.gz")
                    certificate_url = s3.generate_presigned_url("get_object", Params={"Bucket": s3bucket, "Key": domains[0] + "_" + datestamp + ".tar.gz"}, ExpiresIn=345600, HttpMethod="GET")

                    log.info(certificate_url)
                    # Send the email
                    for email in emails:
                        with open(os.path.join("templates/", template)) as email_template:
                            log.info("Sending email to {0}...".format(", ".join(emails)))
                            ses.send_email(Source=from_address, Destination={"ToAddresses": emails}, Message={
                                "Subject": {
                                    "Data": subject,
                                    "Charset": "UTF-8"
                                },
                                "Body": {
                                    "Text": {
                                        "Data": email_template.read().format(url=certificate_url, domain=domains[0], domains=domains),
                                        "Charset": "UTF-8"
                                    }
                                }
                            })

                    # Delete the temp file
                    os.remove(os.path.join(tempdir, domains[0] + ".tar.gz"))
                else:
                    log.info("Skipping " + (" ".join(domains)) + ", certificate not scheduled to be renewed today")

if __name__ == "__main__":
    # Change path to the path of the script
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Set the logging path
    if os.access("/var/log/sslotron.log", os.W_OK):
        log.addHandler(logging.FileHandler("/var/log/sslotron.log"))
    else:
        log.addHandler(logging.FileHandler("/tmp/sslotron.log"))

    # Run the autorenew
    autorenew()
