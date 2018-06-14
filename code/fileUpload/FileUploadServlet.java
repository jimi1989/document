package com.kaishengit.web;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.IOUtils;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.UUID;

@WebServlet("/upload")
public class FileUploadServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.getRequestDispatcher("/WEB-INF/views/upload.jsp").forward(req,resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        //将表单的enctype属性值设置为multipart/form-data之后，
        //会导致request.getParameter()方法无法获取表单元素的值

        //1.文件上传后存放的路径
        File saveDir = new File("D:/upload");
        if(!saveDir.exists()) {
            saveDir.mkdir();
        }
        //2.设置文件上传的临时路径
        File tempDir = new File("D:/tempdir");
        if(!tempDir.exists()) {
            tempDir.mkdir();
        }

        //3.判断表单是否设置enctype属性
        if(ServletFileUpload.isMultipartContent(req)) {

            DiskFileItemFactory itemFactory = new DiskFileItemFactory();
            itemFactory.setSizeThreshold(1024); //缓冲区大小
            itemFactory.setRepository(tempDir); //临时文件路径

            ServletFileUpload servletFileUpload = new ServletFileUpload(itemFactory);
            servletFileUpload.setSizeMax(1024 * 1024 * 10); //上传文件最大体积

            try {
                //获取表单中的所有表单元素(普通元素+文件元素)，包装成FileItem对象
                List<FileItem> fileItemList = servletFileUpload.parseRequest(req);

                for(FileItem item : fileItemList) {
                    if(item.isFormField()) {
                        //普通元素
                        System.out.println("FieldName:" + item.getFieldName());
                        //System.out.println("getString:" + item.getString());
                        System.out.println("getString:" + item.getString("UTF-8"));
                    } else {
                        //文件元素
                        System.out.println("FieldName:" + item.getFieldName()); //获取表单中name属性的值
                        System.out.println("Name:" + item.getName()); //获取上传文件的原始名称(文件名)

                        //获取文件的输入流
                        InputStream inputStream = item.getInputStream();

                        String fileName = item.getName(); //1.jpg
                        String newFileName = UUID.randomUUID().toString() + fileName.substring(fileName.lastIndexOf("."));

                        FileOutputStream outputStream = new FileOutputStream(new File(saveDir,newFileName)); // D:/upload/2.txt

                        IOUtils.copy(inputStream,outputStream);

                        outputStream.flush();
                        outputStream.close();
                        inputStream.close();

                        /*
                        byte[] buffer = new byte[1024];
                        int len = -1;

                        while((len  = inputStream.read(buffer)) != -1) {
                            outputStream.write(buffer,0,len);
                        }

                        outputStream.flush();
                        outputStream.close();
                        inputStream.close();*/

                        System.out.println(item.getName() + "  -> 文件上传成功！");


                    }
                }


            } catch (FileUploadException e) {
                e.printStackTrace();
            }


        } else {
            throw new RuntimeException("form表单enctype属性设置异常");
        }




    }
}
