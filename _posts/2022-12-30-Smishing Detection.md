---
layout: post
title: Smishing Detection Application
description: Malicious message detection application using machine learning model 
tags: PyTorch NLP Android Flutter Dart SQLite  
category: archive
---

### Development Period
23.03.30 ~ 23.12.30

### Technique Stack  
Framework: Flutter, Native, Pytorch  
Language: Dart, Java, Python  

### Details

[Onestore Application](https://m.onestore.co.kr/mobilepoc/apps/appsDetail.omp?prodId=0000766827)   
[Capstone Presentation](https://www.youtube.com/watch?v=ihiws4DuAXg)  
<a href="{{ '/assets/Smishing-Detection-Panel.pdf' | relative_url }}">Capstone Panel</a>

*코드는 회사의 소유로 포함하지 않았습니다.*

### Paper  
<a href="{{ '/assets/Smishing-Detection-using-Aspect-based-Aspect-Extreaction.pdf' | relative_url }}">2022 한국소프트웨어종합학술대회</a>

### Contribution 
1. Permission Request + SMS & MMS 메시지 읽기 기능     
- 유저가 SMS & MMS 읽기 권한 요청 수락 시, Native에서 문자 데이터에 접근하여 Cursor를 통해 모든 문자 읽기  
- 문자 내용을 Flutter에서 띄워주기 위해 Native와 Flutter 간에 Channel을 생성하여 문자 데이터를 전달하도록 구현

2. 스미싱 탐지 기능  
- 전체 문자 데이터를 가져오는데 많은 시간이 소요되어 Channel을 통해 Native에서 Flutter로 문자 데이터 개수를 먼저 전송 후 처리
- 타이머를 걸어 Circular Progress에 검사가 진행되고 있는 상태임을 보여주고, 메세지를 포함한 검사 내용은 
SQLite Database에 저장

3. 출석 체크 기능
Table Calendar 패키지를 사용하여 현재 달과 달력에 출석된 날짜와 월별 출석 수 표시

4. 원클릭 신고 기능 & 다이얼 연결  
- 스미싱에 당하였을 경우, 은행 혹은 경찰서에 전화하여 출금 정지를 할 수 있게 검색을 통해 은행 전화 연결 기능 구현  
- 금융기관 대출 신용카드 조회를 위해 AccountInfo 페이지로 이동 가능하도록 구현 

5. 피싱 뉴스 & 웹 뷰 기능
- 회사가 운영하는 블로그에 피싱 뉴스 기사들을 앱에 보여주기 위해 파이썬을 사용하여 뉴스 데이터 크롤링  
- 블로그로부터 가져온 기사 제목과 기사 내용을 
앱에 리스트 형태로 보여주었고, 클릭 시, 앱에서 웹 뷰를 사용하여 블로그 페이지 뷰

6. SQLite DB 생성 및 연결
- 사용자의 문자 내용은 개인정보에 해당하기 때문에 기밀성을 유지하기 위해 휴대폰 내부 데이터베이스를 생성하여 문자 데이터를 내부 데이터베이스 테이블에 저장
- SQLite 패키지를 사용하여 내부 데이터베이스에 테이블과 쿼리를 수행할 수 있도록 코드 구현

7. 아마존 서버 및 데이터베이스 설정 및 연결  
API를 사용시 결과를 JSON 형태로 뿌리거나 관리자 웹을 구동시키기 위해 Amazon EC2 Ubuntu 서버를 사용하였고, Amazon RDS MariaDB 구축한 후, Flutter와 연결하는 작업 수행

8. UI 작업  
홈, 스미싱 문자 검사, 안심점수, 출석체크, 원클릭 신고, 은행 전화 연결, 은행 번호 문의, 피싱 알림, 알림 설정, 피싱 뉴스, 공지사항 화면 UI 구현  

9. 스미싱 탐지 모델 개발  
Pytorch를 사용하여 문장 임베딩, 속성 임베딩, 정규화 과정을 거쳐 ABAE 모델을 구현하였고, ABAE 모델로 추출된 스미싱 키워드를 활용하여 머신러닝 모델에 학습

### Review  
서로가 서로에게 도움을 줄 수 있었던 것이 너무 좋았던 것 
같다. 모르는 부분이 있으면 배우고, 아는 부분이 있으면 나누고, 해결하지 못한 문제가 있으면 같이 해결해  나아갔다.  

서로 서로 도움을 주고 받으며, 최적의 방안이 무엇인지. 어떻게 하면 이를 효율적으로 처리할 수 있을지. 이러한 방법을 써서 문제를 해결했을 때 발생할 수 있는 문제점은 
무엇인지 등을 서로 고민하며 프로젝트를 진행해갔다. 

최대한 고민을 해보았음에도 해결하지 못한 문제는 교수님께 조언을 구해 해결해 나아가곤 했다. 문제를 해결해 나아가는 과정에서 팀에서 좋은 아이디어가 나오게 되었고, 교수님께서도 연구 방향을 잘 지도해주신 덕분에 KSC 학회에 속성 추출 기반 스미싱 탐지 모델이라는 주제로 일반 논문을 게재할 수 있었다.   

또한, 이 아이디어로 창업 경진 대회에서도 동상을 받고, 캡스톤 페스티벌에서 우수상이라는 좋은 결과를 얻을 수 있었다. 

좋은 팀원과 좋은 지도 교수님을 만난 덕분에 이번 프로젝트를 잘 마무리 할 수 있었다. 

서로 합을 잘 맞춰가고 팀원 모두가 최선을 다했기에 개발과 연구를 동시에 해낼 수 있었던게 아닐까 싶다는 생각이 들었다.

### Achievement  
- KSC 일반 논문 게재 
- 캡스톤 우수상
- 창업 경진대회 동상