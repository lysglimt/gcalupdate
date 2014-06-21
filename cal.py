#!/usr/bin/env python
# -*- coding: utf-8 -*- 

#Modules for working with app engine
import webapp2
import logging

#Python modules
import os
import jinja2

#Project modules
from dbmodels import *
from utilities import *

#For templating
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False)  

def render_str(template, **params):
    """Renders template with parameters"""
    t = jinja_env.get_template(template) 
    return t.render(params)


#REQUEST HANDLERS
class BaseHandler(webapp2.RequestHandler):
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and User.get_by_id(int(user_id))

    """Other handles inherit methods from this handler"""
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s' % (name, cookie_val))    

class Login(BaseHandler):
    def get(self):
        if self.user:
            self.redirect('/main')
        template_values = {}
        self.render('login.html', **template_values)

    def post(self):
        if User.all().count() == 0:
            username = self.request.get('username')
            password = self.request.get('password')
            user = User(username = username, password = password)
            user.put()
            self.redirect('/main')

        username = self.request.get('username')
        password = self.request.get('password')
        user = User.by_username(username)
        if user and user.password == password:
            self.login(user)
            self.redirect('/main')
        self.render('login.html', error = 'Bad password or username')

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s' % (name, cookie_val))

    def read_secure_cookie(self, name):                         #patikrina ar geras cookie
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

class Main(BaseHandler):
    def get(self):
        self.render('main.html', **template_values)

app = webapp2.WSGIApplication([('/', Login),
                               ('/main', Main),
                               ], debug=True)