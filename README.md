以前参考[droid逆向中So模块自动化修复工具+实战一发](https://bbs.kanxue.com/thread-221741.htm)写的python版本so修复工具，原理就是删掉so的section表，根据dynamic重构section，辅助ida分析，只支持32位<br>
用法：修改fixso.py的main函数中的`so_name`为要修复的so路径，然后运行fixso.py
