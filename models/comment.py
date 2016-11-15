from google.appengine.ext import db
from user import User
from post import BlogData
import logging

class Comment(db.Model):
    """Comment Table created by DB which store the comments of blog"""
    commenttext = db.StringProperty(required=True)
    user = db.ReferenceProperty(User)
    blog = db.ReferenceProperty(BlogData)
    date = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, id):
        """To Recieve the Comment by id"""
        comment = Comment.get_by_id(int(id))
        return comment