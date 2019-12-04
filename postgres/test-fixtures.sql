-- Test fixtures

INSERT INTO zones (name, soaprimary, soaemail, soaserial, minlen, maxlen)
	VALUES ('EU.ORG', 'NS.EU.ORG', 'hostmaster.eu.org', '2007110600', 2, 64);
INSERT INTO zones (name, soaprimary, soaemail, soaserial, minlen, maxlen)
	VALUES ('HISTORY.TESTS.EU.ORG', 'NS.EU.ORG', 'hostmaster.eu.org', '2007110600', 2, 64);
INSERT INTO zones (name, soaprimary, soaemail, soaserial, minlen, maxlen)
	VALUES ('DNSSEC.TESTS.EU.ORG', 'NS.EU.ORG', 'hostmaster.eu.org', '2007110600', 2, 64);
INSERT INTO allowed_rr (zone_id, rrtype_id)
	VALUES ((SELECT id FROM zones WHERE name='EU.ORG'), (SELECT id FROM rrtypes WHERE label='NS'));
INSERT INTO allowed_rr (zone_id, rrtype_id)
	VALUES ((SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG'), (SELECT id FROM rrtypes WHERE label='NS'));
INSERT INTO allowed_rr (zone_id, rrtype_id)
	VALUES ((SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG'), (SELECT id FROM rrtypes WHERE label='DS'));
INSERT INTO allowed_rr (zone_id, rrtype_id)
	VALUES ((SELECT id FROM zones WHERE name='HISTORY.TESTS.EU.ORG'), (SELECT id FROM rrtypes WHERE label='NS'));

-- Minimal accounts
--		'$6$1R/p0g2ie3yxya27$ARZEbafeY1J./mbUbOUN1CCf0UsGwsrtq7vTUIGweDuVinXYNpAhUfCvjk2VPM2jSyU4dTpHYtICfFrkyxuYP.',
INSERT INTO contacts (handle, name, email, addr, country, passwd, private)
	VALUES ('TU1', 'Test User', 'tu@foo.bar', 'Test user address\nTest test\n', 'FR',
		'gAAAAABb4bgxslpHR0f59hATY7Jh2MVRsflPb-DQTXJdWM-ds6QmZaAH40eYAN9IkwLA6neRvtl2F_CIHh5Iv4-8mMCZK_ijZqZ6I3S9rTR5PaNvPc_sRXfbpjRMznK5bkRne8B7RJj1sI7XspOnQq5HywHWPX7dWhdMfd0v7u12QzTKXzSDqcoAmgNT5KM-o4aRM-DqYlzB8E4QZf9iQe63NuTgjbz8Kg==',
		true);
INSERT INTO contacts (handle, name, email, addr, country, passwd, private, updated_by)
	VALUES ('TP1', 'Test Person', 'foobaremail@email.bla', 'test address\nline2\nline3\nFrance\n', 'FR',
		'gAAAAABb4bhjNRKUVFgahnCxebm1GJA48oEYbipxz43pRQn-2QA_MNOB373VIEGwtNWyrDlJV0RwrKKB98Ng3yAPYrmgpQLW9EK58QHavTqk1A5VQADSyT79kdgdw3cs3Y4qOon9as1MtMhdR2ruD-8f8PbeSl5_hZC4n3oscqm_lNbsqT9j1dxgqCncloy6OeFb5iCeeG5cEtRPXVEXAmLZWZj_A7aCTg==',
		true, '::1');
INSERT INTO contacts (handle, name, email, addr, country, passwd, private)
	VALUES ('TR1', 'Test Registrant', NULL, 'Test user address\nTest test\n', 'FR', NULL, true);

-- Test account with a long handle
INSERT INTO contacts (handle, name, email, addr, country, passwd, private, updated_by)
	VALUES ('ZZ1111', 'Test Person2', 'foobaremail2@email.bla', 'test address 2\nline2\nline3\nFrance\n', 'FR',
		'$6$yMosWhub11BviiGi$ecmu3CHjI6WkUvLOgtLF/80Y.mupkMGDIXdL6ChhR1iCCcLEQF7mLWtOeECvrcIpH2S/cWAJUpDAoJjFRxuUg0',
		true, '::1');

-- Unvalidated account
INSERT INTO contacts (handle, name, email, addr, country, passwd, private, updated_by, validated_on)
	VALUES ('UA1', 'Unvalidated Account', 'foobaremail4@email.bla', 'test address\nline2\nline3\nUnited Kingdom\n', 'UK',
		'$6$sHB3M.T.MvSzm9aQ$2q6Sz7X3qKaUmOhVsQt2LFQ/abKZ.cRNXb6vZiZB7prBLFydtdDbGh/amfo5GN1q8QQd0hX0ArZHj63p9Mqgc1',
		true, '::1', NULL);
-- Old style (passwordless) account
INSERT INTO contacts (handle, name, email, addr, country, passwd, private, updated_by, validated_on)
	VALUES ('OA1', 'Old Account', 'foobaremail5@email.bla', 'test address\nline2\nline3\nBelgium\n', 'BE',
		NULL,
		true, '::1', NULL);


-- Admin account
INSERT INTO contacts (handle, name, email, addr, country, passwd, private, updated_by)
	VALUES ('AA1', 'Admin Account', 'foobaremail3@email.bla', 'test address 3\nline2\nline3\nFrance\n', 'FR',
		'$6$JHG/n2FuXShwJPo1$KLQoUvEy7/hLLMcNkvBgLZpj9cpPmtv0V64fDRnzoySgZ4MR1laCy.1/ZNY.q2oeU9yWuDFc2xgmKih5rLXVt0',
		true, '::1');
INSERT INTO admins (login, contact_id) VALUES('AA1', (SELECT id FROM contacts WHERE handle='AA1'));

-- zone apex
INSERT INTO domains (name, zone_id)
	VALUES ('', (SELECT id FROM zones WHERE name='HISTORY.TESTS.EU.ORG'));
INSERT INTO domains (name, zone_id)
	VALUES ('', (SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG'));
INSERT INTO domains (name, zone_id)
	VALUES ('', (SELECT id FROM zones WHERE name='EU.ORG'));

INSERT INTO domains (name, zone_id)
	VALUES ('NS', (SELECT id FROM zones WHERE name='EU.ORG'));
INSERT INTO domains (name, zone_id)
	VALUES ('NS', (SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG'));

INSERT INTO rrs (domain_id, rrtype_id, label, value)
	VALUES ((SELECT id FROM domains WHERE name=''
                  AND zone_id=(SELECT id FROM zones WHERE name='EU.ORG')),
		(SELECT id FROM rrtypes WHERE label='NS'), '', 'NS.EU.ORG');
-- glue in EU.ORG
-- NS.EU.ORG. A 192.168.0.15
INSERT INTO rrs (domain_id, rrtype_id, label, value)
	VALUES ((SELECT id FROM domains WHERE name=''
                  AND zone_id=(SELECT id FROM zones WHERE name='EU.ORG')),
		(SELECT id FROM rrtypes WHERE label='A'), 'NS', '192.168.0.15');

INSERT INTO rrs (domain_id, rrtype_id, label, value)
	VALUES ((SELECT id FROM domains WHERE name='NS'
                  AND zone_id=(SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG')),
		(SELECT id FROM rrtypes WHERE label='NS'), '', 'DNSSEC.TESTS.EU.ORG');
INSERT INTO rrs (domain_id, rrtype_id, label, value)
	VALUES ((SELECT id FROM domains WHERE name=''
                  AND zone_id=(SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG')),
		(SELECT id FROM rrtypes WHERE label='NS'), '', 'NS1.DNSSEC.TESTS.EU.ORG');
-- glue in DNSSEC.TESTS.EU.ORG
-- NS1.DNSSEC.TESTS.EU.ORG. A 192.168.0.15
INSERT INTO rrs (domain_id, rrtype_id, label, value)
	VALUES ((SELECT id FROM domains WHERE name=''
                  AND zone_id=(SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG')),
		(SELECT id FROM rrtypes WHERE label='A'), 'NS1', '192.168.0.15');
-- NS1.DNSSEC.TESTS.EU.ORG. AAAA 2001:db8:4::1:1
INSERT INTO rrs (domain_id, rrtype_id, label, value)
	VALUES ((SELECT id FROM domains WHERE name=''
                  AND zone_id=(SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG')),
		(SELECT id FROM rrtypes WHERE label='AAAA'), 'NS1', '192.168.0.15');

INSERT INTO whoisdomains (fqdn) VALUES ('NS.DNSSEC.TESTS.EU.ORG');
INSERT INTO domain_contact (whoisdomain_id, contact_id, contact_type_id)
	VALUES ((SELECT id FROM whoisdomains WHERE fqdn = 'NS.DNSSEC.TESTS.EU.ORG'),
		(SELECT id FROM contacts WHERE handle='TU1'),
		(SELECT id FROM contact_types WHERE name='technical'));

INSERT INTO domains (name, zone_id) VALUES ('NONS', (SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG'));
INSERT INTO whoisdomains (fqdn) VALUES ('NONS.DNSSEC.TESTS.EU.ORG');
INSERT INTO domain_contact (whoisdomain_id, contact_id, contact_type_id)
	VALUES ((SELECT id FROM whoisdomains WHERE fqdn = 'NONS.DNSSEC.TESTS.EU.ORG'),
		(SELECT id FROM contacts WHERE handle='TU1'),
		(SELECT id FROM contact_types WHERE name='technical'));


-- domain history
INSERT INTO domains (id, name, zone_id)
	VALUES (10, 'H1', (SELECT id FROM zones WHERE name='HISTORY.TESTS.EU.ORG'));
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, NULL, 1, '1997-01-06 15:11:38.94+01', '', '192.168.0.2', '1997-10-14 10:42:24.87+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, NULL, 1, '1997-10-14 10:42:24.87+02', '', '192.168.0.2', '1997-12-14 19:20:34.97+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, NULL, 28, '1997-10-14 10:42:24.87+02', '', '2001:db8:4::1:f', '1997-12-14 19:20:34.97+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, NULL, 1, '1997-12-14 19:20:34.97+01', '', '192.168.0.2', '2000-02-29 21:16:02.93+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 3600, 28, '1997-12-14 19:20:34.97+01', '', '2001:db8:4::1:f', '2000-02-29 21:16:02.93+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 60, 28, '2000-02-29 21:16:02.93+01', '', '2001:db8:4::1:f', '2008-07-21 13:45:16.62+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, NULL, 1, '2000-02-29 21:16:02.93+01', '', '192.168.0.2', '2008-07-21 13:45:16.62+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 1, '2008-07-21 13:45:16.62+02', '', '192.168.0.2', '2008-08-05 10:38:02.88+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 60, 28, '2008-07-21 13:45:16.62+02', '', '2001:db8:4::1:f', '2008-08-05 10:38:02.88+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 7200, 1, '2008-08-05 10:38:02.88+02', '', '192.168.1.3', '2008-11-29 19:32:30.54+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 7200, 28, '2008-08-05 10:38:02.88+02', '', '2001:db8:4::1:f', '2008-11-29 19:32:30.54+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 7200, 1, '2008-11-29 19:32:30.54+01', '', '192.168.1.3', '2008-11-29 19:42:55.64+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 28, '2008-11-29 19:32:30.54+01', '', '2001:db8:4::1:f', '2008-11-29 19:42:55.64+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 7200, 1, '2008-11-29 19:42:55.64+01', '', '192.168.1.3', '2008-11-30 00:26:13.73+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 60, 28, '2008-11-29 19:42:55.64+01', '', '2001:db8:4::1:f', '2008-11-30 00:26:13.73+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 7200, 1, '2008-11-30 00:26:13.73+01', '', '192.168.1.3', '2008-12-01 21:25:05.71+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 60, 28, '2008-11-30 00:26:13.73+01', '', '2001:db8:4::1:2', '2008-12-01 21:25:05.71+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 7200, 1, '2008-12-01 21:25:05.71+01', '', '192.168.1.3', '2008-12-02 00:52:54.18+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 7200, 28, '2008-12-02 00:52:54.18+01', '', '2001:db8:4::1:2', '2009-01-06 21:58:50.77+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 7200, 1, '2008-12-02 00:52:54.18+01', '', '192.168.1.3', '2009-01-06 21:58:50.77+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 7200, 1, '2009-01-06 21:58:50.77+01', '', '192.168.1.3', '2014-03-21 23:20:30.59+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 7200, 28, '2009-01-06 21:58:50.77+01', '', '2001:db8::4:3', '2014-02-28 23:20:30.59+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 1, '2014-02-28 23:20:30.59+01', '', '192.168.1.3', '2014-03-23 17:56:47.08+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 28, '2014-02-28 23:20:30.59+01', '', '2001:db8::4:3', '2014-03-23 17:56:47.08+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 28, '2014-03-23 17:56:47.08+01', '', '2001:db8::4:3', '2014-04-28 21:17:29.12+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 1, '2014-03-23 17:56:47.08+01', '', '192.168.2.6', '2014-04-28 21:17:29.12+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 28, '2014-04-28 21:17:29.12+02', '', '2001:db8::0:3', '2014-05-03 01:52:19.84+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 1, '2014-04-28 21:17:29.12+02', '', '192.168.2.6', '2014-05-03 01:52:19.84+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, NULL, 1, '2014-05-03 01:52:19.84+02', '', '192.168.2.6', '2015-05-19 18:22:31.05+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, NULL, 28, '2014-05-03 01:52:19.84+02', '', '2001:db8::0:3', '2015-05-19 18:22:31.05+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, NULL, 28, '2015-05-19 18:22:31.05+02', '', '2001:db8::0:4', '2015-09-21 17:24:15.93+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, NULL, 1, '2015-05-19 18:22:31.05+02', '', '192.168.2.6', '2016-02-29 23:30:25.09+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 28, '2015-09-21 17:24:25.06+02', '', '2001:db8::0:4', '2015-09-23 17:17:36.11+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, NULL, 28, '2015-10-02 20:28:07.89+02', '', '2001:db8::0:4', '2016-02-29 23:30:25.09+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 3600, 28, '2016-02-29 23:30:25.09+02', '', '2001:db8::0:4', '2016-10-01 00:38:32.06+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 3600, 1, '2016-02-29 23:30:25.09+02', '', '192.168.2.6', '2016-10-01 00:38:32.06+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 28, '2016-10-01 00:38:32.06+02', '', '2001:db8::0:4', '2016-10-01 11:43:33.99+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 1, '2016-10-01 00:38:32.06+02', '', '192.168.2.6', '2016-10-01 11:43:33.99+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 3600, 28, '2016-10-01 11:43:33.99+02', '', '2001:db8::1:4', '2016-10-02 15:19:22.75+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 3600, 28, '2016-10-01 11:43:33.99+02', '', '2001:db8::1:4', '2017-09-27 12:17:10.44+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 3600, 1, '2016-10-01 11:43:33.99+02', '', '192.168.2.6', '2017-09-27 12:17:10.44+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 3600, 1, '2017-09-27 12:17:10.44+02', '', '192.168.2.6', '2018-02-01 13:25:39.16+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 28, '2017-09-27 12:17:10.44+02', '', '2001:db8::1:4', '2018-02-01 13:25:39.16+01');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 3600, 1, '2018-02-01 13:25:39.16+01', '', '192.168.2.6', '2018-06-20 22:05:35.43+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 3600, 28, '2018-06-06 13:19:43.95+02', '', '2001:db8::1:4', '2018-06-21 18:50:09.05+02');
INSERT INTO rrs_hist (domain_id, ttl, rrtype_id, created_on, label, value, deleted_on) VALUES (10, 600, 1, '2018-06-20 22:05:43.44+02', '', '192.168.4.1', '2018-06-21 13:55:42.73+02');
INSERT INTO rrs (domain_id, ttl, rrtype_id, created_on, label, value, id) VALUES (10, 600, 28, '2018-06-21 18:50:17.33+02', '', '2001:db8::1:4', 585542);
INSERT INTO rrs (domain_id, ttl, rrtype_id, created_on, label, value, id) VALUES (10, 600, 1, '2018-06-21 13:55:51.75+02', '', '192.168.2.6', 585532);

INSERT INTO whoisdomains (fqdn) VALUES ('H1.HISTORY.TESTS.EU.ORG');
INSERT INTO domain_contact (whoisdomain_id, contact_id, contact_type_id)
	VALUES ((SELECT id FROM whoisdomains WHERE fqdn = 'H1.HISTORY.TESTS.EU.ORG'),
		(SELECT id FROM contacts WHERE handle='TU1'),
		(SELECT id FROM contact_types WHERE name='technical'));
INSERT INTO domain_contact (whoisdomain_id, contact_id, contact_type_id)
	VALUES ((SELECT id FROM whoisdomains WHERE fqdn = 'H1.HISTORY.TESTS.EU.ORG'),
		(SELECT id FROM contacts WHERE handle='TR1'),
		(SELECT id FROM contact_types WHERE name='registrant'));

ALTER SEQUENCE domains_id_seq RESTART with 56;
