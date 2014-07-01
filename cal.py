#!/usr/bin/env python
# -*- coding: utf-8 -*- 
"""
When calling Calendar API - send correct timezone
"""
#Python modules
import webapp2
import logging
import httplib2
import sys

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
        
    def read_secure_cookie(self, name): #checks validity of cookie
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


class Main(BaseHandler):
    @decorator.oauth_aware
    def get(self):
        if not self.user:
            self.redirect('/')
            return
        if ClientSecrets.all().count() == 0:
            self.redirect('/enter_client_secret')
            return
        if not decorator.has_credentials():
            self.redirect('/grant_permission')
            return      

        calendar_names_and_ids = []
        calendars = []
        template_values = {}
        page_token = None
        while True:
            try: #Quick fix for invalid_grant
                calendar_list = service.calendarList().list(pageToken=page_token).execute(http=decorator.http())
            except client.AccessTokenRefreshError:
                logging.error('Problem getting calendar list. Redirecting to permission grant page. Error: AccessTokenRefreshError')
                self.redirect('/grant_permission')                
                return
            for calendar_list_entry in calendar_list['items']:
                id = calendar_list_entry.get('id')
                if id != '#contacts@group.v.calendar.google.com':
                    calendar_names_and_ids.append({                                                     #in future remove duplication of saving the same calendar id information 
                                               'name' : calendar_list_entry.get('summary'),
                                               'id' : id,
                                               })
                calendars.append(calendar_list_entry.get('id'))
            page_token = calendar_list.get('nextPageToken')
            if not page_token:
                break
                calendar = self.request.get('calendar')
        
        current_cal_id = 'primary'
        if not self.read_secure_cookie('calendar'):
            logging.info('Setting Calendar cookie for first time')
            self.set_secure_cookie('calendar', str(current_cal_id))
        cookie_calendar = self.read_secure_cookie('calendar')
        selected_calendar = self.request.get('calendar')
        if cookie_calendar in calendars and cookie_calendar != '':
            current_cal_id = cookie_calendar
        if selected_calendar in calendars and selected_calendar != '':
            current_cal_id = selected_calendar
            self.set_secure_cookie('calendar', str(selected_calendar))        

        query_params = {
                        'calendarId' : current_cal_id,
                        'timeZone' : 'Europe/Oslo',
                        'calendarId' : current_cal_id,
                        }
        calendar_start_date = self.request.get('start')
        calendar_end_date = self.request.get('end')
        if calendar_start_date:
            template_values['start'] = calendar_start_date
            query_params['timeMin'] = calendar_start_date + 'T00:00:00.00Z'
        if calendar_end_date:
            template_values['end'] = calendar_end_date
            query_params['timeMax'] = calendar_end_date + 'T00:00:00.00Z'
        all_events = []
        query_params['pageToken'] = None
        while True:            
            events = service.events().list(**query_params).execute(http=decorator.http())
            calendar_name = events['summary']
            for event in events['items']:
                start_time = event['start'].get('dateTime')
                end_time = event['end'].get('dateTime')
                if start_time and end_time:                    
                    start_time = start_time[:-9]
                    end_time = end_time[:-9]
                else:
                    start_time = event['start'].get('date')
                    end_time = event['end'].get('date')
                all_events.append({
                                   'summary' : event.get('summary'),
                                   'start_date' : event['start'].get('date'),
                                   'start_time' : start_time,
                                   'time_zone' : event['start'].get('timeZone') or '',
                                   'end_date' : event['end'].get('date'),
                                   'end_time' : end_time,
                                   'location' : event.get('location'),
                                   'id' : event.get('id'),
                                   })
            page_token = events.get('nextPageToken')
            if not page_token:
                break     

        template_values.update({'all_events' : all_events[::-1], #[::-1] reverses list so the date go from most resent at the top
                           'calendar_names_and_ids' : calendar_names_and_ids,
                           'calendar_name' : calendar_name,
                           })
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
        self.render('event_editor.html', **template_values)

    @decorator.oauth_aware
    def post(self):
        ""
        calendar = self.read_secure_cookie('calendar')

        errors = []

        start_date = self.request.get('startdate')
        end_date = self.request.get('enddate')
        start_time = self.request.get('starttime')
        end_time = self.request.get('endtime')
        time_zone = self.request.get('timezone')
        summary = self.request.get('summary')
        location = self.request.get('location')
        description = self.request.get('description')

        event = {
                'summary': summary,
                'location': location,
                'description': description,
                }

        if start_time and end_time :
            event['start'] = {
                              'dateTime' : start_date + 'T' + start_time + ':00',
                              'timeZone' : time_zone,  
                              }
            event['end'] = {
                            'dateTime' : end_date + 'T' + end_time + ':00',
                            'timeZone' : time_zone,
                            }
        else:
            event['start'] = {'date' : start_date}
            event['end'] = {'date' : end_date}
        try:
            service.events().insert(calendarId=calendar, body=event).execute(http=decorator.http())
        except:
            logging.error(sys.exc_info()[1])
            errors.append('Check your input data')
            template_values = {
                               'errors' : errors,
                               'start_date' : start_date,
                               'end_date' : end_date,
                               'start_time' : start_time,
                               'end_time' : end_time,
                               'time_zone' : time_zone,
                               'summary': summary,
                               'location': location,
                               'description': description,
                               }
            logging.info('Problematic template values: ' + str(template_values))
            self.render('event_editor.html', **template_values)
            return
        self.redirect('/main')

class RemoveEvent(BaseHandler):
    @decorator.oauth_aware
    def get(self):
        ""
        id = self.request.get('id')
        calendar = self.read_secure_cookie('calendar')

        service.events().delete(calendarId=calendar, eventId=id).execute(http=decorator.http())
        self.redirect('/main')

class EditEvent(BaseHandler):
    @decorator.oauth_aware
    def get(self):
        ""
        event_id = self.request.get('id')
        calendar_id = self.read_secure_cookie('calendar')

        event = service.events().get(calendarId=calendar_id, eventId=event_id, timeZone='Europe/Oslo').execute(http=decorator.http())

        start_time = event['start'].get('dateTime')
        end_time = event['end'].get('dateTime')
        if start_time and end_time:
            start_date = start_time[:10]
            end_date = end_time[:10]                    
            start_time = start_time[11:-9]
            end_time = end_time[11:-9]
        else:
             start_date = event['start'].get('date')
             end_date = event['end'].get('date')
        template_values = {
                            'summary' : event.get('summary'),
                            'description' : event.get('description'),
                            'start_date' : start_date,
                            'start_time' : start_time or '',
                            'time_zone' : event['start'].get('timeZone') or '',
                            'end_date' : end_date,
                            'end_time' : end_time or '',
                            'location' : event.get('location'),
                            'id' : event.get('id'),
                            'sequence' : event.get('sequence')
                            }

        self.render('event_editor.html', **template_values)

    @decorator.oauth_aware
    def post(self):
        ""
        calendar = self.read_secure_cookie('calendar')

        errors = []

        start_date = self.request.get('startdate')
        end_date = self.request.get('enddate')
        start_time = self.request.get('starttime')
        end_time = self.request.get('endtime')
        time_zone = self.request.get('timezone')
        summary = self.request.get('summary')
        location = self.request.get('location')
        description = self.request.get('description')
        event_id = self.request.get('id')        

        incrimented_sequence = str(int(self.request.get('sequence')) + 1)

        event = {
                'summary': summary,
                'location': location,
                'description': description,
                'sequence': incrimented_sequence,
                }

        if start_time and end_time :
            event['start'] = {
                              'dateTime' : start_date + 'T' + start_time + ':00',
                              'timeZone' : time_zone,  
                              }
            event['end'] = {
                            'dateTime' : end_date + 'T' + end_time + ':00',
                            'timeZone' : time_zone,
                            }
        else:
            event['start'] = {'date' : start_date}
            event['end'] = {'date' : end_date}
        try:
            service.events().update(calendarId=calendar, eventId=event_id, body=event).execute(http=decorator.http())
        except:
            logging.error(sys.exc_info()[1])
            errors.append('Check your input data')
            template_values = {
                               'errors' : errors,
                               'start_date' : start_date,
                               'end_date' : end_date,
                               'start_time' : start_time,
                               'end_time' : end_time,
                               'time_zone' : time_zone,
                               'summary': summary,
                               'location': location,
                               'description': description,
                               'sequence': incrimented_sequence,
                               }
            logging.info('Problematic template values: ' + str(template_values))
            self.render('event_editor.html', **template_values)
            return
        self.redirect('/main')

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