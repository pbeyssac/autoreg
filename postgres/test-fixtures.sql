-- Test fixtures

INSERT INTO zones (name, soaprimary, soaemail, soaserial, minlen, maxlen)
	VALUES ('EU.ORG', 'NS.EU.ORG', 'hostmaster.eu.org', '2007110600', 2, 64);
INSERT INTO zones (name, soaprimary, soaemail, soaserial, minlen, maxlen)
	VALUES ('DNSSEC.TESTS.EU.ORG', 'NS.EU.ORG', 'hostmaster.eu.org', '2007110600', 2, 64);
INSERT INTO allowed_rr (zone_id, rrtype_id)
	VALUES ((SELECT id FROM zones WHERE name='EU.ORG'), (SELECT id FROM rrtypes WHERE label='NS'));
INSERT INTO allowed_rr (zone_id, rrtype_id)
	VALUES ((SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG'), (SELECT id FROM rrtypes WHERE label='NS'));
INSERT INTO allowed_rr (zone_id, rrtype_id)
	VALUES ((SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG'), (SELECT id FROM rrtypes WHERE label='DS'));

-- Minimal accounts
INSERT INTO contacts (handle, name, email, addr, country, passwd, private)
	VALUES ('TU1', 'Test User', 'tu@foo.bar', 'Test user address\nTest test\n', 'FR',
		'$6$1R/p0g2ie3yxya27$ARZEbafeY1J./mbUbOUN1CCf0UsGwsrtq7vTUIGweDuVinXYNpAhUfCvjk2VPM2jSyU4dTpHYtICfFrkyxuYP.',
		true);
INSERT INTO contacts (handle, name, email, addr, country, passwd, private, updated_by)
	VALUES ('TP1', 'Test Person', 'foobaremail@email.bla', 'test address\nline2\nline3\nFrance\n', 'FR',
		'$6$SDUcSDXhMqWxJHby$RF2s62JKIjqEhcmxqMq9ShhtTXaSr1sKdz3BMv5c/dx3J6Mn0fNVsClbugDEJnUsH301nilTqH1OKcABiBfMC.',
		true, '::1');

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


-- Admin account
INSERT INTO contacts (handle, name, email, addr, country, passwd, private, updated_by)
	VALUES ('AA1', 'Admin Account', 'foobaremail3@email.bla', 'test address 3\nline2\nline3\nFrance\n', 'FR',
		'$6$JHG/n2FuXShwJPo1$KLQoUvEy7/hLLMcNkvBgLZpj9cpPmtv0V64fDRnzoySgZ4MR1laCy.1/ZNY.q2oeU9yWuDFc2xgmKih5rLXVt0',
		true, '::1');
INSERT INTO admins (login, contact_id) VALUES('AA1', (SELECT id FROM contacts WHERE handle='AA1'));

-- zone apex
INSERT INTO domains (name, zone_id)
	VALUES ('', (SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG'));
INSERT INTO domains (name, zone_id)
	VALUES ('', (SELECT id FROM zones WHERE name='EU.ORG'));

INSERT INTO domains (name, zone_id)
	VALUES ('NS', (SELECT id FROM zones WHERE name='DNSSEC.TESTS.EU.ORG'));

INSERT INTO rrs (domain_id, rrtype_id, label, value)
	VALUES ((SELECT id FROM domains WHERE name='NS'),
		(SELECT id FROM rrtypes WHERE label='NS'), '', 'NS.EU.ORG');
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
