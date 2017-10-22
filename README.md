# xnu-struct
Attempts to extract structures from C code and annotate them with the fields offsets.

To test:
python fustruct.py <file.c> >test_file.c
clang++ -Xclang -ast-dump -fsyntax-only test_file.c >/dev/null

If errors would indicate where script failed to properly rewrite the structures.
