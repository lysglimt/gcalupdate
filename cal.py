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

#For templating
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False)  

def render_str(template, **params):
    """Renders template with parameters"""
    t = jinja_env.get_template(template) 
    return t.render(params)


#REQUEST HANDLERS
class BaseHandler(webapp2.RequestHandler):
    """Other handles inherit methods from this handler"""
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))


class Login(BaseHandler):
    def get(self):
        template_values = {}
        self.render('login.html', **template_values)

    def post(self):
        have_error = False
        params = {}

        username = self.request.get('username')
        password = self.request.get('password')

app = webapp2.WSGIApplication([('/', Login),
                               ], debug=True)