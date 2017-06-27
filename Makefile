msg:
	./autoreg/arf/manage.py makemessages -v3 -a -e html,mail,py --ignore build
compilemsg:
	./autoreg/arf/manage.py compilemessages

install-locale:
	(tar cf - locale) | (cd /usr/local/autoreg/arf/; tar xfv -)

install-templates:
	tar cf - templates | (cd /usr/local/autoreg/arf/; tar xfv -)
