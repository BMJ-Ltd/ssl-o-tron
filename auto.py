#!/usr/bin/env python3

from __future__ import print_function

from configparser import ConfigParser
from OpenSSL import crypto

import boto3
import tempfile
import yaml
import os
import datetime
import sslotron


if __name__ == "__main__":

    today = datetime.date.today()
    datestamp = today.strftime("%Y%m%d")

    s3bucket = sslotron.config.get("aws", "s3_bucket")

    try:
        boto_settings = {
            "aws_access_key_id": sslotron.config.get("aws", "aws_access_key_id"),
            "aws_secret_access_key": sslotron.config.get("aws", "aws_secret_access_key"),
            "region_name": sslotron.config.get("aws", "aws_region")
        }
    except:
        boto_settings = {
            "region_name": sslotron.config.get("aws", "aws_region")
        }

    s3 = boto3.client("s3", **boto_settings)
    ses = boto3.client("ses", **boto_settings)


    with open(sslotron.certificatesfile) as yamlfile:
        # Load YAML file
        yaml_documents = yaml.safe_load_all(yamlfile)

        for document in yaml_documents:

            if type(document.get("domains")) is str:
                domains = [document.get("domains")]
            else:
                domains = document.get("domains")

            if type(document.get("emails")) is str:
                emails = [document.get("emails")]
            else:
                emails = document.get("emails")

            if type(document.get("cc")) is str:
                cc = [document.get("cc")]
            else:
                cc = document.get("cc")

            from_address = document.get("from", sslotron.config.get("defaults", "email_from"))
            subject      = document.get("subject", sslotron.config.get("defaults", "email_subject"))
            template     = document.get("template", sslotron.config.get("defaults", "email_template"))
            rsa          = document.get("rsa", sslotron.config.get("defaults", "rsa"))
            days_ahead   = document.get("days_ahead", sslotron.config.get("defaults", "days_ahead"))

            renew = sslotron.renew_soon(domains, datetime.timedelta(days=int(days_ahead)))

            # If we need to renew
            if renew:

                time_left = renew.days

                with tempfile.TemporaryDirectory() as tempdir:
                
                    outputfile = os.path.join(tempdir, domains[0] + ".tar.gz")
                            
                    # Generate a tar file containing a cert and private key for the domain;
                    tar = sslotron.get_cert_tar(outputfile, domains, rsa)

                    # Upload the certificate package to Amazon S3
                    sslotron.log.info("Uploading certificate to Amazon S3...")
                    s3.upload_file(tar, s3bucket, domains[0] + "_" + datestamp + ".tar.gz")
                    certificate_url = s3.generate_presigned_url("get_object", Params={"Bucket": s3bucket, "Key": domains[0] + "_" + datestamp + ".tar.gz"}, ExpiresIn=345600, HttpMethod="GET")
                    sslotron.log.info(certificate_url)

                    # Send the email
                    for email in emails:
                        with open(os.path.join("templates/", template)) as email_template:

                            sslotron.log.info("Sending email to {0}...".format(", ".join(emails)))
                            
                            if cc is not None:
                              email_destination = {"ToAddresses": emails, "CcAddresses": cc}
                            else:
                              email_destination = {"ToAddresses": emails}

                            try:
                                ses.send_email(Source=from_address, Destination=email_destination, Message={
                                    "Subject": {
                                        "Data": subject,
                                        "Charset": "UTF-8"
                                    },
                                    "Body": {
                                        "Text": {
                                            "Data": email_template.read().format(url=certificate_url, domain=domains[0], domains=domains, time_left=time_left, s3bucket=s3bucket),
                                            "Charset": "UTF-8"
                                        }
                                    }
                                })
                            except:
                                sslotron.log.error("Issue encountered when sending email for " + domains[0] + "!")

                    # Send a slack notification (if it's configured)
                    if sslotron.config.has_option("slack", "url"):
                        sslotron.slack(sslotron.config.get("slack", "url"), domains, time_left, certificate_url)


            else:
                sslotron.log.info("Skipping " + (" ".join(domains)) + ", certificate doesn't expire soon.")