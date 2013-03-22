Python模拟浏览器登录
====================

通过读取浏览器的cookie，可以支持访问大多数通过cookie保存登录的网站。class ContentEncodingProcessor 来自http://obmem.info/?p=753

###目前支持新浪微博的登录

可以通过cookie登录，也可以通过RSA方式直接登录，并保存登录成功后的cookie。

###使用方法

修改XXX为自己的用户名和密码，修改浏览器cookie的路径，见注释。默认使用cookie登录，也可以直接使用RSA加密登录。
