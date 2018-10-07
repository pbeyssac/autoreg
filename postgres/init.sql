--
-- Database initialization
--

-- dummy "root" zone used as a placeholder to catch domains
-- for which we store only whois data
INSERT INTO zones (name, minlen, maxlen, soaserial, soaprimary, soaemail) VALUES ('', 1, 255, 2005113000, 'DUMMY', 'DUMMY');

-- same as RFC (wire) RR type
INSERT INTO rrtypes values (1, 'A');
INSERT INTO rrtypes values (2, 'NS');
INSERT INTO rrtypes values (5, 'CNAME');
INSERT INTO rrtypes values (12, 'PTR');
INSERT INTO rrtypes values (13, 'HINFO');
INSERT INTO rrtypes values (15, 'MX');
INSERT INTO rrtypes values (16, 'TXT');
INSERT INTO rrtypes values (28, 'AAAA');
INSERT INTO rrtypes values (33, 'SRV');
INSERT INTO rrtypes values (37, 'CERT');
INSERT INTO rrtypes values (39, 'DNAME');
INSERT INTO rrtypes values (43, 'DS');
INSERT INTO rrtypes values (44, 'SSHFP');
INSERT INTO rrtypes values (46, 'RRSIG');
INSERT INTO rrtypes values (48, 'DNSKEY');
INSERT INTO rrtypes values (52, 'TLSA');
INSERT INTO rrtypes values (59, 'CDS');
INSERT INTO rrtypes values (60, 'CDNSKEY');
INSERT INTO rrtypes values (99, 'SPF');
INSERT INTO rrtypes values (257, 'CAA');
INSERT INTO rrtypes values (32769, 'DLV');
-- private range
INSERT INTO rrtypes values (65280, 'WMX');


INSERT INTO contact_types VALUES (1,'technical');
INSERT INTO contact_types VALUES (2,'administrative');
INSERT INTO contact_types VALUES (3,'zone');
INSERT INTO contact_types VALUES (4,'registrant');


INSERT INTO admins (id,login) VALUES (0,'*unknown*');
INSERT INTO admins (id,login) VALUES (1,'autoreg');
ALTER SEQUENCE admins_id_seq RESTART with 2;
