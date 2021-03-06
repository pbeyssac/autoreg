AutoReg 0.4
===========

Autoreg (formerly known as AutoReg 4.1, short name AR41, now retired),
is the software that's been running most of *eu.org* since 1996.

The current version requires:

	* Python >= 3.6
	* Django >= 2.1
	* BIND >= 9.12
	* Postfix >= 3.2 (or another mail-transfer agent if you convert
          postgres/postfix-handles.cf)
	* Postgres >= 10
	* a web server running WSGI

*PRELIMINARY*, many bits are missing.

Autoreg can be installed with `./setup.py install`, or from a pre-wrapped
package (Python egg, etc).

Required Python modules are listed in `setup.py`

1. Install the Python package, then the additional shell scripts in `bin/`

2. Create Unix userids for *autoreg* and *whois*

3. Create a Postgres database, run:
	`psql $(database) < postgres/autoreg.schema`
	`psql $(database) < postgres/init.sql`

3b. Create ENCRYPT_KEY and SECRET_KEY
	`python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' > /usr/local/autoreg/arf/ENCRYPT_KEY`
	`python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())' > /usr/local/autoreg/arf/SECRET_KEY`

4. Configure a web server with WSGI.

   See configurations (with Apache sample) in `sample-files/`

5. The DNS zone files are generated in `/etc/namedb/autoreg/`

6. create a Django superuser account with necessary permissions
   to access the request list.

7. enable cron jobs from `sample-files/crontab`
