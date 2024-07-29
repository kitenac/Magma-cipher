Magma cipher implementation in OFB mode.

Program tests it`s perfomance of crypt + decrypt in two tests:
  TEST #1 on files of size 1MB, 100MB
  TEST #2 on file of fixed size with changing cipher key each: 10, 100, 1000 blocks

Also all key and subkey info deletes (zeroing) ASAP

ps in Main.java you can find tests for each cipher`s core subfunction, program creates 1,100,1000MB files for tests 
