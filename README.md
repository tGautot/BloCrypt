# Blocrypt


## Encrypted File Format

 0       1       2       3       4       5       6       7       
+----------------------------------------------------------------+
|   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .    |
|   File Data, some blocks encrypted                             |
|   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .    |
+----------------------------------------------------------------+


## key.store File Format

 0       1       2       3       4       5       6       7       
+----------------------------------------------------------------+
| Key Count
+----------------------------------------------------------------+
 ***  Following repeated for KeyCount times ***
| Block Start
+----------------------------------------------------------------+
| Block End
+----------------------------------------------------------------+
| BNS    | Block Name ...
| ...
+----------------------------------------------------------------+
| KeySz  | KeyData ...
| ...
+----------------------------------------------------------------+

BNS: BlockNameSize; number of bytes for block's name

## Tests
 You can find tests in the `tests` folder, make sure you have boost installed as it is required for the tests. On ubuntu you can install boost via:
 > sudo apt-get install libboost-all-dev