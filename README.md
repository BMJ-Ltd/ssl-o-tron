SSL-O-Tron
==========

The SSL-O-Tron is an all-in-one solution for providing
Let's Encrypt certificates to vendors via email without
human intervention, for domains with their DNS inside
Amazon Route 53, and email using Amazon SES.

This is a Python 3 application, based on 
[acme-dns-tiny](https://projects.adorsaz.ch/adrien/acme-dns-tiny/),
and is designed to be run as a daily cron job.

How it works
============

The script checks against certificates.yaml for any
entries that match the current day of the month.

If it matches, the script then passes the DNS challenge
by adding the record to the domain via the Route 53 API,
and then removes it once successful.

A tarball is made of the certificate and private key,
uploaded to an Amazon S3 bucket, then an expiring link
is emailed to the address(es) listed in the entry using
the Amazon SES API.

Configuration
=============

A sample configuration file can be found in config/config.ini.
This tests against Let's Encrypt's staging servers, and
the certificates it outputs are invalid.

You can leave `aws_access_key_id` and `aws_secret_access_key`
blank if you're using [Boto's configured access keys](https://boto3.readthedocs.io/en/latest/guide/configuration.html).

`certificates.yaml` is the list of certificates and where
you want them sent to.

* **domains** is a list of domain names to request certificates for. Their DNS should be in Route 53 so the challenge can be passed.
* **day** is the day of the month you want the renewal to occur on. It should be a number from 1 to 28.
* **from** is the email address you want to see in the From field. Useful for emailing support ticket systems.
* **emails** is the email address(es) you want the certificates to be sent to.
* **subject** is the subject line of the email
* **template** is filename of the email template you want to use. default.tmpl is included, but you may want to write your own.

Email templates
===============

Email templates use Python's format() string substitution. Variables to substitute are defined in curly braces, e.g. `{variable}`.

SSL-O-Tron will substitute the following variables:

* **url** with the download link
* **domain** with the first domain in the list.
* **domains** with a space separated list of domains.


