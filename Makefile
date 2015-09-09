msg:
	./autoreg/arf/manage.py makemessages -v3 -a -e html,mail,py --ignore build
compilemsg:
	./autoreg/arf/manage.py compilemessages
