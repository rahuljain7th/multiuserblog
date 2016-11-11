import webapp2
from postBlog import BlogFormHandler,EditBlog,DeleteBlog
from getBlog import GetAllBlog,GetBlogbyId,MyBlog
from signup import SignupForm
from login import Logout,Login
from comment import CommentHandler
from like import LikePostHandler
import logging

"""Defining the Url Route to Handler"""
app = webapp2.WSGIApplication([
    ('/blog', GetAllBlog),
    ('/newpost', BlogFormHandler),
    (r'/(\d+)', GetBlogbyId),
    ('/signup', SignupForm),
    ('/login', Login),
    ('/logout', Logout),
    ('/myblogs', MyBlog),
    ('/editblog', EditBlog),
    ('/deleteblog', DeleteBlog),
    ('/comment', CommentHandler),
    ('/likepost', LikePostHandler),
    ('/', GetAllBlog)
    ], debug=True)