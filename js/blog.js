 function postcomment(forminput) {
                $.ajax({
                  type: "POST",
                  url: "/blog/comment",
                  dataType: 'json',
                  data: JSON.stringify({ "blogId": forminput.blogId.value,"comment":forminput.commentText.value})
                }).done(function(data) {
                    if(data.redirect) {
                        $(forminput).children('.commentList').append('<div class="errorMsg">please login to post</div>');
                    } else {
                    $(forminput).children('.commentList').append('<div class="postedcomment">'+data['commenttext']+'</div>');
                }

                });
            }
            function increaseLike(blogId) {
                $.ajax({
                    type:"POST",
                    url:"/blog/likepost",
                    dataType:'json',
                    data:JSON.stringify({"blogId":blogId})
                }).done(function(data) {
                    alert(data.errorMsg)

                    if(data.errorMsg) {
                        document.getElementById('errorMsg-'+blogId).innerHTML=data.errorMsg;
                    } else {
                        alert(data.totalLikes)
                        document.getElementById('likecount-'+blogId).innerHTML=data.totalLikes;

                    }
                });
            }

