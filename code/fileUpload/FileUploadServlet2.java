package com.kaishengit.web;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;

@WebServlet("/upload2")
@MultipartConfig
public class FileUploadServlet2 extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.getRequestDispatcher("/WEB-INF/views/upload2.jsp").forward(req,resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        String desc = req.getParameter("desc");

        //根据name属性值获取对应的part对象
        Part part = req.getPart("file");
        System.out.println("getName:" + part.getName()); //name属性值
        System.out.println("getContentType:" + part.getContentType()); //文件的MIME类型
        System.out.println("getSize:" + part.getSize()); //上传文件的体积（字节）
        System.out.println("getSubittedFileName:" + part.getSubmittedFileName()); //获取上传的文件名

        //System.out.println(FileUtils.byteCountToDisplaySize(part.getSize()));
        File saveDir = new File("D:/upload");
        if(!saveDir.exists()) {
            saveDir.mkdir();
        }

        String fileName = part.getSubmittedFileName();
        String newName = UUID.randomUUID().toString() + fileName.substring(fileName.lastIndexOf("."));

        InputStream inputStream = part.getInputStream();
        FileOutputStream outputStream = new FileOutputStream(new File(saveDir,newName));

        IOUtils.copy(inputStream,outputStream);

        outputStream.flush();
        outputStream.close();
        inputStream.close();

        System.out.println(fileName + "  -> upload success!");


    }
}
