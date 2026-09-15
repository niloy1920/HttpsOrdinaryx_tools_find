# HttpsOrdinaryx_tools_find
This tools is only educational


termux run 

pkg update
pkg install python
git clone https://github.com/niloy1920/HttpsOrdinaryx_tools_find
pip install requests rich
python niloy.py

useing cli

python niloy.py --target https://YOUR-LAB-SITE.example --full

SQL test

python ordinaryx.py --target "https://YOUR-LAB-SITE.example/page?id=1" --sql

create report 

python ordinaryx.py --target https://YOUR-LAB-SITE.example --full --report report.json
