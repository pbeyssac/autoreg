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

INSERT INTO contacts (handle, name, email, addr, country, passwd, private)
	VALUES ('TU1', 'Test User', 'tu@foo.bar', 'Test user address\nTest test\n', 'FR',
		'$6$1R/p0g2ie3yxya27$ARZEbafeY1J./mbUbOUN1CCf0UsGwsrtq7vTUIGweDuVinXYNpAhUfCvjk2VPM2jSyU4dTpHYtICfFrkyxuYP.',
		true);

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
