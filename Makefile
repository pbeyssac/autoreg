msg:
	./autoreg/arf/manage.py makemessages -v3 -a -e html,mail,py --ignore build
compilemsg:
	./autoreg/arf/manage.py compilemessages

install-locale:
	(tar cf - locale) | (cd /usr/local/autoreg/arf/; tar xfv -)

install-templates:
	tar cf - templates | (cd /usr/local/autoreg/arf/; tar xfv -)

preparedb:
	echo "drop database test_autoreg_dev;" | psql -h 192.168.0.4 --user autoreg postgres
	echo "create database test_autoreg_dev;" | psql -h 192.168.0.4 --user autoreg postgres
	(cat postgres/autoreg.schema; ./tools/mkiso.py) | psql -h 192.168.0.4 --user autoreg test_autoreg_dev

test:	preparedb
	./autoreg/arf/manage.py test -k --settings autoreg.arf.arf.debugsettings
