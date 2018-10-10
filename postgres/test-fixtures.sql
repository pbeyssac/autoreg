-- Test fixtures

INSERT INTO zones (name, soaprimary, soaemail, soaserial, minlen, maxlen) VALUES ('EU.ORG', 'NS.EU.ORG', 'hostmaster.eu.org', '2007110600', 2, 64);
INSERT INTO allowed_rr (zone_id, rrtype_id) VALUES ((SELECT id FROM zones WHERE name='EU.ORG'), (SELECT id FROM rrtypes WHERE label='NS'));
