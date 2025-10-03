## LiveURLDeduper

### 1.直接使用

搭配subfinder食用更佳，将如下的子域名文件导入即可。日常自己处理老跑脚本去重有点麻烦，所以拷打大模型搓了个gui

![image-20251003125123318](C:\Users\天\Downloads\URL去重工具\img\image-20251003125123318.png)

### 2.自行编译、改进源码

使用pyinstaller打包，命令如下，我用的是python 3.11没啥毛病

```
pyinstaller --onefile --windowed --name "LiveURLDeduper" --icon=myicon.ico url_deduplicator_gui.py
```

### 3.广告：低价考各类安全证书咨询wx：abcd2477231995

在就业竞争白热化的当下，一本高含金量证书就是你脱颖而出的利器！我们提供 CISP 系列、CISSP、软考、PMP、ISO27001 等热门认证服务，无论是信息安全、项目管理还是体系认证需求都能满足。组团报考享超值优惠，支持对公转账开票，学生报考 PTE 更有专属低价。早考早拿证，为简历镀金，敲开名企大门，机会不等人，速来咨询！
