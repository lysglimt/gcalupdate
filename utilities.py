#!/usr/bin/env python
# -*- coding: utf-8 -*- 
import hashlib
import hmac
import random
import re
from string import letters

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def make_salt(length = 5):
    return u''.join(random.choice(letters) for x in xrange(length))

def make_secure_val(val):
    secret = 'saugiau'
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):              #patikrina ar geras secure_val
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val