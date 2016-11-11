from bloghandler import BlogHandler
from models import comment,user,post
import logging

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
            comment = Comment(commenttext=comment,
                              user=user, blog=blogData)
            comment.put()
            self.response.out.write(json.dumps(({'commenttext':
                                                comment.commenttext})))
        else:
            logging.debug("Redirect to login")
            self.response.out.write(json.dumps(({'redirect': 'true'})))
