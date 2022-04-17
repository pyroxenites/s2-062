# s2-062
远程代码执行S2-062 CVE-2021-31805验证POC

验证方式
![image](https://user-images.githubusercontent.com/75877299/163505291-bb028a4f-19dd-4133-a82d-89c8032cecbc.png)
![image](https://user-images.githubusercontent.com/75877299/163513359-934f75f9-7022-4599-bcc7-d78fbb39f74a.png)


vulfocus靶场问题
poc里面是验证s2-061靶场的，参数为id，新靶场参数为name

判断是id主要是因为想不到windows和linux有什么好的通用命令回显判断特征

靶场应该是无回显的原因，所以看不到指令
不过可以反弹shell和dnslog探测
![b3f8c3552d8a7577358369546979eb4](https://user-images.githubusercontent.com/75877299/163654319-15c45139-121b-470f-acd4-3fde0631d539.png)

![63b34cd006f6daf25a6972f7f0ca4e1](https://user-images.githubusercontent.com/75877299/163654325-9b3df7c7-e528-4fe4-b0d1-0b6687ce9700.png)


针对无回显的
![image](https://user-images.githubusercontent.com/75877299/163706557-95fdbc8b-cc08-492d-9650-d8499c7c3111.png)
![image](https://user-images.githubusercontent.com/75877299/163706568-4bc8508a-3cf2-4dca-aebb-d198fd64e8af.png)
