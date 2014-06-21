#!/usr/bin/env python
# -*- coding: utf-8 -*-
#App engine modules 
from google.appengine.ext import db

#My modules
#from utilities import * #padaryti import utilities as ut

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_username(cls, username):
        user = User.all().filter('username =', username).get() #get() gražina tik viena objektą, ne sarašąfeatures every image gallery
        return user

"""
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def register(cls, username, password, email = None):      #takses parameters and creates user object
        pw_hash = make_pw_hash(username, password)
        return User(username = username,
                    password = pw_hash,
                    email = email)

    @classmethod
    def get_user(cls, name, pw):
        user = cls.by_username(name)                   #cls calls its own class
        if user and valid_pw(name, pw, user.password): #if user exists and its valid password
            return user                            #returns user

    @classmethod
    def by_username(cls, username):
        user = User.all().filter('username =', username).get() #get() gražina tik viena objektą, ne sarašąfeatures every image gallery
        return user

class Picture(db.Model):
    tema = db.StringProperty(required = True)
    pavadinimas = db.StringProperty()
    komentaras = db.StringProperty()
    ikele = db.StringProperty(required = True)
    pic_url = db.LinkProperty()
    pic = db.BlobProperty()
    rating = db.IntegerProperty()
    tags = db.ListProperty(item_type = str)

    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def add_tags(self, tags):
        tag_set = set()
        for tag in tags:
            tag_set.add(tag)
        for tag in tag_set:
            if tag not in self.tags:
                self.tags.append(tag)

    def delete_tag(self, tag):
        if tag in self.tags:
            self.tags.remove(tag)


class Tag(db.Model):
    tag = db.StringProperty(required = True)
    count = db.IntegerProperty(required = True)
    pic_ids = db.ListProperty(item_type = int)

    @staticmethod
    def update_tags(tags, picture_id):
        for t in tags:
            tag = Tag.all().filter('tag =', t).get()
            if tag:
                if picture_id not in tag.pic_ids:
                    tag.pic_ids.append(picture_id)
                    tag.count += 1
                    tag.put()
            else:
                tag = Tag(tag = t, count = 0)
                tag.count += 1
                tag.pic_ids.append(picture_id)
                tag.put()

    @staticmethod
    def delete_tag(tag, picture_id):
        tag = Tag.all().filter('tag =', t).get()
        tag.pic_ids.remove(picture_id)
        tag.put()

    #@classmethod 
    #def create(cls, tags, picture_id):
    #    tag = Tag(pic_id = picture_id)
    #    if tags:
    #        for t in tags:
    #            if t not in tag.tags:
    #                tag.tags.append(t)
    #    return tag

"""