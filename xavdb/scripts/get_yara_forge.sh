wget -P ../db/ https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip
cd ../db/
unzip yara-forge-rules-extended.zip
mv packages/extended/yara-rules-extended.yar .
rm -rf packages/ yara-forge-rules-extended.zip
