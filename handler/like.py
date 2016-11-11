from bloghandler import BlogHandler
from models import user
from models import post
from models import like

class LikePostHandler(BlogHandler):
    """To Handle the Like Functionality of the Blog"""
    def post(self):
        logging.debug("Liking the Post")
        data = json.loads(self.request.body)
        blogId = data['blogId']
        # check if user is loggedIn.
        if self.isvalid_login():
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            blogData = BlogData.by_id(int(blogId))
            if blogData.user and blogData.user.username != user.username:
                if blogData.isPostAlreadyLikedByUser(blogId, user_id):
                    self.response.out.write(json.dumps(({'errorMsg':
                                            'You Have Already Liked the Post'
                                                         })))
                else:
                    likeBlog = LikeBlog(userid=user_id,
                                        blogid=blogId, isLikedBlog=True)
                    likeBlog.put()
                    totallikes = blogData.incrementLike(blogId)
                    self.response.out.write(json.dumps(
                                           ({'totalLikes': totallikes})))
            else:
                self.response.out.write(json.dumps(
                                                  ({'errorMsg': 'You Cannot' +
                                                   'Like your own post'})))
        else:
            logging.debug("Redirect to login")
            self.response.out.write(json.dumps(
                                   ({'errorMsg': 'Login to Like Post'})))