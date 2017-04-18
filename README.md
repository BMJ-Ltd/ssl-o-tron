SSL-O-Tron
==========

The SSL-O-Tron is an automated solution for reminding responsible parties to renew Let's Encrypt certificates in an 
environment where the actual process of updating the certificate is performed manually or handled by an external party.

Domains must have their DNS inside Amazon Route 53. Reminders are sent via email (Amazon SES).

This is a Python 3 application, based on 
[acme-dns-tiny](https://projects.adorsaz.ch/adrien/acme-dns-tiny/),
and is designed to be run as a daily cron job.

How it works
============

`auto.py` runs through certificates.yaml, identifying certifcates that are close to expiry.

Once an expiring cert is found, the script then passes the DNS challenge
by adding the record to the domain via the Route 53 API,
and then removes it once successful.

A tarball is made of the certificate and private key,
uploaded to an Amazon S3 bucket, then an expiring link
is emailed to the address(es) listed in the entry using
the Amazon SES API.

Configuration
=============

A sample configuration file can be found in config/config.ini. This tests against Let's Encrypt's staging servers, and 
the certificates it outputs are invalid.

You can omit `aws_access_key_id` and `aws_secret_access_key` if you're using [Boto's configured access keys](https://boto3.readthedocs.io/en/latest/guide/configuration.html).

SSL-0-Tron supports 2048-bit and 4096-bit RSA encryption keys. The path to these keys should be set with `key2048` 
and `key4096`. If they don't exist, the script will generate them for you.

Default values for various parameters can be set under `[defaults]`.

`certificates.yaml` is the list of certificates and where
you want them sent to.

* **domains** is a list of domain names to request certificates for. Their DNS should be in Route 53 so the challenge can be passed.
* **from** is the email address you want to see in the From field. Useful for emailing support ticket systems.
* **emails** is the email address(es) you want the certificates to be sent to.
* **cc** is the email address(es) you would like to CC on the email
* **subject** is the subject line of the email
* **template** is filename of the email template you want to use. default.tmpl is included, but you may want to write your own.
* **days_ahead** is the number of days out from expiry you would like to receive an email
* **rsa** is the level of RSA encryption the private key should use

Email templates
===============

Email templates use Python's format() string substitution. Variables to substitute are defined in curly braces, e.g. `{variable}`.

SSL-O-Tron will substitute the following variables:

* **url** with the download link
* **domain** with the first domain in the list.
* **domains** with a space separated list of domains.
* **time_left** with the days until the certificate expires
* **s3bucket** with the name of the S3 bucket

Slack
===============

In addition to emails, you can optionally send notifications to a Slack room via an 
[Incoming Webhook](https://api.slack.com/incoming-webhooks). Just add `url = https//hooks.slack.com/services/YOUR/URL/HERE` 
under `[slack]` in config.ini.

Limitations
===============

Assuming you run `auto.py` as a daily cron task, reminders will be sent every day until the certificate is renewed. 
This could be seen as helpful insistence or an unwelcome annoyance depending on who is receiving the emails.