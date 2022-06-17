# VUT_FIT-ISA_POP3client
Projekt POP3 clienta s TLS do predmetu ISA (Síťové aplikace a správa sítí)

Program bude umoznovat citanie elektronickej posty cez protokol s rozsireniami POP3S a POP3 STARTTLS,
po spusteni stiahne spravy ulozene na servery a ulozi ich kazdu zvlast do zadaneho adresara.
Na standardny vystup sa vypise pocet stiahnutych sprav. Programovu funkcionalitu je mozne menit
pomocou dodatocnych parametrov.


Spustenie programu ( adresar obsahujuci certifikacne subory musi byt najprv rehashnuty prikazom: "c_rehash <zlozka>" )
  
  
    obecny priklad spustenia:
  
    ./popcl mail.local -o <vystupny adresar> -a <subor s autorizacnymi udajmi>
