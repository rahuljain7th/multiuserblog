from bloghandler import BlogHandler
from models import comment,user,post
from models.user import User
from models.post import BlogData
from models.comment import Comment
import logging
import json

class CommentHandler(BlogHandler):
    """To Handle the Comment Functionality of the Blog"""
    def post(self):
        logging.debug("Inside Comment handler Post method")
        data = json.loads(self.request.body)
        comment = data['comment']
        blogId = data['blogId']
        if self.isvalid_login():
            # TODO: Refactor to getUser Method Later to get user object
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            # TODO: Refactor to getBlogbyId method to getBlogData Object
            blogId = data['blogId']
            blogData = BlogData.by_id(int(blogId))
            if blogData:
                comment = Comment(commenttext=comment,
                              user=user, blog=blogData)
                comment.put()
                self.response.out.write(json.dumps(({'commenttext':
                                                comment.commenttext})))
            else:
                self.response.out.write(json.dumps(({'error':
                                                "This Blog doesnt Exists"})))
        else:
            logging.debug("Redirect to login")
            self.response.out.write(json.dumps(({'redirect': 'true'})))


class DeleteCommentHandler(BlogHandler):
    """To Handle the Comment Functionality of the Blog"""
    def post(self):
        logging.debug("Inside Delete Comment handler Post method")
        data = json.loads(self.request.body)
        commentId = data['commentId']
        if self.isvalid_login():
            # TODO: Refactor to getUser Method Later to get user object
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            comment = Comment.by_id(int(commentId))
            # TODO: Refactor to getBlogbyId method to getBlogData Object
            if comment and comment.user and comment.user.username == user.username:
                        comment.delete()
                        self.response.out.write(json.dumps(({'success':
                                                'true'})))
            else:
                self.response.out.write(json.dumps(({'errorMsg':
                                                "You cannot Delete This Comment"})))
        else:
            logging.debug("Redirect to login")
            self.response.out.write(json.dumps(({'errorMsg': 'Login to Delete Comment'})))

class EditCommentHandler(BlogHandler):
    """To Handle the Edit Comment Functionality of the Blog"""
    def post(self):
        logging.debug("Inside Edit Comment handler Post method")
        data = json.loads(self.request.body)
        commentId = data['commentId']
        editcommenttext = data['comment']
        if self.isvalid_login():
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            comment = Comment.by_id(int(commentId))
            if comment and comment.user and comment.user.username == user.username:
                comment.commenttext=editcommenttext
                comment.put()
                self.response.out.write(json.dumps(({'success':
                                       'true'})))
            else:
                self.response.out.write(json.dumps(({'errorMsg':
                                                "You cannot Edit This Comment"})))
        else:
            logging.debug("Redirect to login")
            self.response.out.write(json.dumps(({'errorMsg': 'Login to Edit Comment'})))