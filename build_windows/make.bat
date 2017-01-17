cl /c /Ox /Os /GL /GF /GS- /Wall /EHsc ../src/msspi.cpp
link /DLL /LTCG msspi.obj crypt32.lib advapi32.lib /OUT:msspi.dll
