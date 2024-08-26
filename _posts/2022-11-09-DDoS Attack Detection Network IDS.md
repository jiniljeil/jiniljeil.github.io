---
layout: post
title: DDoS Attack Detection Network IDS
description: DDoS Attack Detection NIDS using Neural Network
tags: IDS ML DDoS Detection
category: archive
---

### Development Period
22.11.09 ~ 22.12.16

### Technique Stack  
Framework: Tensorflow   
Language: Python   
Module: [cicflowmeter](https://github.com/datthinh1801/cicflowmeter)

### Demonstration Video
[Youtube](https://youtu.be/wBjDQ6sChoc)

### Details

[Document](https://github.com/OH318/DoS-Intrusion-Detection-System/blob/master/IDS%20Final%20Report.pdf)  
[Github](https://github.com/OH318/DoS-Intrusion-Detection-System.git)  
[Dataset](https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv?select=02-16-2018.csv)

### Contribution

- Python Sniffer 모듈에 모델 삽입  
    패킷 수신 시, 추출된 데이터를 Normailization 과정을 거쳐 모델에 입력으로 넘기고, 모델에서 나온 결과 값을 Softmax()를 통해 공격 유형 파악

- Feature Extraction  
    공격 유형을 결정짓는 Feature가 무엇인지 분석

- Neural Network Model  
    DDoS Attack Dataset로 학습 진행 후, 학습된 모델 추출 

    - Optimizer   
        Adam optimizer
    - Preprocessing  
        X(input) -> Normalization   
    - Model Structure   
        Dense(relu) -> Dense(sigmoid) -> Dropout(0.2) -> Dense(softmax)
    - Training ( 7 : 3, Train Set(7) : Test Set(3) )   
        Epochs: 10, Batch_size: 10
### Review

IDS는 NIDS, HIDS로 나뉘며, 각각 어떤 구조로 동작하는지 알게되었다. 

*HIDS Open Source Project : Tripwire  
파일 내용을 Hash 형태로 DB에 저장하여 Hash 값이 달라진 파일들의 목록을 보여주어 침해 시도가 발생했는지 알 수 있다.* 

*NIDS Open Source Project : snort  
패킷 데이터를 분석하여 Rule과 일치하는지 확인하여 차단하는 방식을 추구한다.*

Rule을 적용한 Snort와는 달리, 인공지능을 활용하여 NIDS를 구현하여 DDoS Attack을 탐지를 수행하였고, cicoflowmeter sniffer 내부에 모델을 추가하는 과정에서 sniffer 내부 구조도 이해하게 되었다.