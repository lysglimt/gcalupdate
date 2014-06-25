#!/usr/bin/env python
# -*- coding: utf-8 -*- 

#Python modules
import webapp2
import logging
import httplib2

from apiclient import discovery
from oauth2client import appengine
from oauth2client import client
from google.appengine.api import memcache

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

logging.info('#0')

client_id=''
client_secret=''
if ClientSecrets.all().count() != 0:
    client_details = ClientSecrets.all().get()
    client_id = client_details.client_id
    client_secret = client_details.client_secret

http = httplib2.Http(memcache)
service = discovery.build('calendar', 'v3', http=http)
decorator = appengine.OAuth2Decorator(
    client_id=client_id,
    client_secret=client_secret,
    scope=[
      'https://www.googleapis.com/auth/calendar',
      'https://www.googleapis.com/auth/calendar.readonly',
    ])

logging.info('#1')

#REQUEST HANDLERS
class BaseHandler(webapp2.RequestHandler):
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and User.get_by_id(int(user_id))

    """Other handles inherit methods from this handler"""
    def render(self, template, **kw):
        if self.user:
            kw['logged_in'] = True
        self.response.out.write(render_str(template, **kw))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s' % (name, cookie_val))   
        
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=')

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

    def read_secure_cookie(self, name):                         #checks validity of cookie
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

class Main(BaseHandler):
    @decorator.oauth_aware
    def get(self):
        logging.info('#2')
        if not self.user:
            self.redirect('/')
            return
        if ClientSecrets.all().count() == 0:
            self.redirect('/enter_client_secret')
            return
        if not decorator.has_credentials():
            self.redirect('/grant_permission')
            return
        logging.info('#3')
        all_events = []
        page_token = None
        while True:
            events = service.events().list(calendarId='primary', pageToken=page_token).execute(http=decorator.http())
            for event in events['items']:
                all_events.append({
                                   'summary' : event.get('summary'),
                                   'date' : event['start'].get('date'),
                                   'location' : event.get('location'),
                                   'id' : event.get('id'),
                                   })
            page_token = events.get('nextPageToken')
            if not page_token:
                break

        template_values = {'all_events' : all_events[::-1]} #[::-1] reverses list so the date go from most resent at the top
        self.render('main.html', **template_values)


class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class ClientSecret(BaseHandler):
    def get(self):
        ""
        template_values = {}
        self.render('enter_client_secret.html', **template_values)

    def post(self):
        ""
        client_id = self.request.get('client_id')
        client_secret = self.request.get('client_secret')

        secret = ClientSecrets(client_id = client_id, client_secret = client_secret)
        secret.put()
        decorator._client_id = client_id
        decorator._client_secret = client_secret
        self.redirect('/grant_permission')


class GrantPermission(BaseHandler):
    @decorator.oauth_aware
    def get(self):
        ""
        template_values = {
            'url': decorator.authorize_url(),
            'has_credentials': decorator.has_credentials()
            }
        self.render('grant_permission.html', **template_values)


class AddEvent(BaseHandler):
    @decorator.oauth_aware
    def get(self):
        ""
        template_values = {}
        self.render('add_event.html', **template_values)

    @decorator.oauth_aware
    def post(self):
        ""
        start_date = self.request.get('date')
        end_date = start_date[:-1] + str(int(start_date[-1:]) + 1) #increments date by one
        
        event = {
                'summary': self.request.get('summary'),
                'location': self.request.get('location'),
                'description': self.request.get('description'),
                'start': {
                            'date': start_date
                            },
                'end': {
                            'date': end_date
                            },
                }
        service.events().insert(calendarId='primary', body=event).execute(http=decorator.http())
        self.redirect('/main')

class RemoveEvent(BaseHandler):
    @decorator.oauth_aware
    def get(self):
        ""
        id = self.request.get('id')
        service.events().delete(calendarId='primary', eventId=id).execute(http=decorator.http())
        self.redirect('/main')

class EditEvent(BaseHandler):
    @decorator.oauth_aware
    def get(self):
        ""

app = webapp2.WSGIApplication([('/', Login),
                               ('/main', Main),
                               ('/logout', Logout),
                               ('/enter_client_secret', ClientSecret),
                               ('/grant_permission', GrantPermission),
                               ('/add', AddEvent),
                               ('/edit', EditEvent),
                               ('/remove', RemoveEvent),
                               (decorator.callback_path, decorator.callback_handler()),
                               ], debug=True)

#Only needed for logging.debug() to show up in logs
def main():
    # Set the logging level in the main function
    # See the section on Requests and App Caching for information on how
    # App Engine reuses your request handlers when you specify a main function
    logging.getLogger().setLevel(logging.DEBUG)
    webapp.util.run_wsgi_app(application)

if __name__ == '__main__':
    main()