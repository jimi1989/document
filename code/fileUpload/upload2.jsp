<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Document</title>
</head>
<body>
    <h3>文件上传</h3>
    <ul>
        <li>文件上传的表单method属性值必须为post</li>
        <li>文件上传控件使用的是input元素type属性值为file</li>
        <li>将文件上传的表单form元素的enctype属性值设置为multipart/form-data</li>
    </ul>
    <form action="/upload2" method="post" enctype="multipart/form-data">
        <input type="text" name="desc"> <br>
        <input type="file" name="file"> <br>
        <button>上传</button>
    </form>

    <img src="/download?file=c5724829-8d04-4c72-9c94-da64460cb5f2.jpg" height="200" alt="">
    
    <a href="/download?file=c5724829-8d04-4c72-9c94-da64460cb5f2.jpg&name=you.jpg">下载照片</a>
    <a href="/download?file=我的照片.jpg">下载我的照片</a>
    <a href="/download?file=my.pdf">下载PDF文件</a>
    <a href="/download?file=commons-collections4-4.1-bin.zip">下载zip文件</a>
</body>
</html>