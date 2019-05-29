#!/usr/bin/python
#activate_this = '/var/www/FlaskApp/venv/bin/activate_this.py'
#with open(activate_this) as file_:
#    exec(file_.read(), dict(__file__=activate_this))
import sys
import logging

sys.stdout = sys.stderr

logging.basicConfig(stream=sys.stderr)
#sys.path.insert(0, "/usr/bin/")        
sys.path.insert(0,"/var/www/FlaskApp/")

print("Hello There")
print(sys.path)

from FlaskApp import app as application
