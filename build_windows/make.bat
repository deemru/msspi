cl /c /Ox /Os /GL /GF /GS- /Wall /EHa /I../third_party/cprocsp/include -DMSSPI_USE_MSSPI_CERT ../src/msspi.cpp
link /DLL /LTCG msspi.obj crypt32.lib advapi32.lib /OUT:msspi.dll
