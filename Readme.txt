
Refernce links:
https://www.c-sharpcorner.com/article/token-based-authentication-using-web-api-2-owin-and-identity/
https://www.ecanarys.com/Blogs/ArticleID/308/Token-Based-Authentication-for-Web-APIs
http://www.advancesharp.com/blog/1236/asp-net-web-api-2-owin-oauth-bearer-token-refresh-token-with-custom-database
http://www.advancesharp.com/blog/1216/oauth-web-api-token-based-authentication-with-custom-database

Step1: create table in ourdatabase(UserMasters)
Step2: set it in web.config
Step3: Install Owin packages

Microsoft.Owin.Host.SystemWeb
Microsoft.Owin.Security.OAuth
Microsoft.Owin.Cors
Newtonsoft.json

Step4: Create Model class and Mapper class as well.


Step5: Create DbContext class and implement that mapper in "onmodelcreating" 
Step6:




-----------------------------------------------------------------------------------------------------------ASP.Net WebAPI.--
clientside tokenvm.cs


server  -> webapi  -> username,passowrd, token (response --> token ,refreshtoken, exptime,etc..)
client  --> endopoint

store token 
