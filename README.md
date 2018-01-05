# Silvio Text Infectction Technic
Implementation of Silvio Cesare text infection technic.

Current implementation is for infecting ELF64 files.

# Important
You should not use it for creating small viruses but only to know how this technic works.

# Algorithm
1- Increase the section header offset by PAGE_SIZE in the ELF file header.

2- Locate the text segment program header:

  - Modify the entry point to the parasite location.
  - Increase file size and memory size in the text segment program header by the size of the parasite.
  
3- For each program header whose segment is after the parasite, increase it's offset by PAGE_SIZE.

4- Find the last section header in the text segment and increase it's size by the length of the parasite.

5- For every section header that exists after the parasite insertion, increase it's offset by PAGE_SIZE.

6- Insert the parasite code into the text segment.
