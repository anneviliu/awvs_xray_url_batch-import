# awvs_xray_url_batch-import
用于解决awvs和xray联动时url批量导入的小脚本

## 使用方法
修改`main.py`中的`awvs_url`,`Cookie`,并设置xray监听的ip和端口号.

在当前目录下新建`url.txt`文件 用于存放需要批量导入的url.

```bash
python3 main.py 
```

即可完成批量导入并开始扫描。
