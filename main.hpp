/**
 * Název:            main.hpp
 * Předmět:          Síťové aplikace a správa sítí
 * Instituce:        VUT FIT
 * Autor:            Pavel Bobčík
 * Login:            xbobci03
 * Vytvořeno:        18. října 2021
 */

#ifndef MAIN
#define MAIN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <regex>
#include <string>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"

using namespace std;
using namespace std::regex_constants;
#include "parser.hpp"

#define DEFAULT_PORT "110"
#define DEFAULT_SSL_PORT "995"
#define BUFFER 1024
#define UIDLIST_FILE "messageUidsList.txt"

#define MESSAGE_END "\r\n"
#define MESSAGE_USER "USER "
#define MESSAGE_PASS "PASS "
#define MESSAGE_STAT "STAT" MESSAGE_END
#define MESSAGE_RETR "RETR "
#define MESSAGE_UIDL "UIDL "
#define MESSAGE_DELE "DELE "
#define MESSAGE_STLS "STLS" MESSAGE_END
#define MESSAGE_QUIT "QUIT" MESSAGE_END

/**
 * Funkce kontroluje, zdali se jedná o složku, nikoliv o soubor.
 * Dále zdali zvolená složka existuje na uvedeném místě. Pokud ne, vytvoří novou složku s uvedeným názvem.
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 *
 * Funkce byla inspirována z:
 * Zdroj:   Stack Overflow
 * Dotaz:   https://stackoverflow.com/q/18100097
 * Odpověď: https://stackoverflow.com/a/18101042
 * Autor:   Ingo Leonhardt
 * Autor:   https://stackoverflow.com/users/2470782/ingo-leonhardt
 * Datum:   7. srpena 2013
 */
int checkOutputDir();

/**
 * Funkce pro zahájení POP3 komunikace se serverem.
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int connectPOP3();

/**
 * Funkce pro zahájení SSL komunikace se serverem.
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int connectSSL();

/**
 * Funkce pro zahájení TLS komunikace se serverem.
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int connectTLS();

/**
 * Funkce pro vytvoření SSL_CTX a nastavení certifikátu.
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int getCtx();

/**
 * Funkce pro kontrolu certifikátu obdrženého ze serveru.
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int checkCert();

/**
 * Funkce zprostředukjící odesílání požadavků na server.
 * @param message požadavek, jenž má být zaslán
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int sendMessage(string message);

/**
 * Funkce zprostředkující příjmání odpovědí ze serveru.
 * @param messageBuffer ukazatel na pole charů pro odpověď ze serveru
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int readMessage(char *messageBuffer);

/**
 * Funkce spojující server a port.
 * @param defaultPort výchozí port, jenž se využije, není-li uveden přepínač -p
 * @return string obsahující server:port
 */
string getHostName(string defaultPort);

/**
 * Funkce zprostředkovávající komunikaci se serverem pro příkazy USER a PASS.
 * Včetně kontroly, zdali došlo k úspěšnému připojení.
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int login();

/**
 * Funkce provádějící kontrolu a získání přihlašovacích údajů ze souboru.
 * @param user ukazatel na textový řetězec pro uživatelské jméno
 * @param pass ukazatel na textový řetězec pro uživatelské heslo
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int getAuthInfo(string &user, string &pass);

/**
 * Funkce pro zpracování stažení a následné uložení zpráv a to včetně Message-ID.
 * @param msgCnt počet zpráv ke stažení
 * @param msgCntr ukazatel na číselnou hodnotu obsahující počet stažených zpráv
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int getMails(int &msgCntr);

/**
 * Funkce pro získání počtu zpráv na serveru pomocí zprávy STAT.
 * @return int reprezentující počet zpráv, nebo -1 v případě chyby.
 */
int getMsgCount();

/**
 * Funkce zpracovávájící příchozí data ze serveru po odeslání požadavku RETR.
 * Ukládá data do obdržení příznaku konce zprávy. Ten je následně odstraněn.
 * @param msgNumber číslo stahované zprávy
 * @param msg ukazatel na textový řetězec pro staženou zprávu
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int downloadMsg(int msgNumber, string &msg);

/**
 * Začíná-li nový řádek tečkou, tak bude obsahovat o tečku více. Funkce se stárá
 * o její vyhledání a v případě výskytu o její redukování.
 * @param msg ukazatel na textový řetězec pro staženou zprávu
 */
void removeByteStuffing(string &msg);

/**
 * Funkce pro extrahování Message-ID z obdržené zprávy.
 * @param msg textový řetězec obsahující staženou zprávu
 * @return string obsahující id, nebo prázdný řetězec v případě chyby
 */
string getMsgId(string msg);

/**
 * Funkce kontrolující, jestli se jedná o novou zprávu.
 * Hledá obdržené Message-ID v souboru uchovávajícím Message-ID stažených zpráv.
 * @param id Message-ID
 * @return bool hodnotu true/false, zdali se jedná o novou/starou zprávu
 */
bool isNewMail(string id);

/**
 * Funkce zasílá zprávu serveru informující o tom, kterou zprávu má nastavit na smazání.
 * @param msgNumber číslo zprávy, jenž má být smazána
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int setMsgToDelete(int msgNumber);

/**
 * Funkce extrahuje název předmětu zprávy, jenž je využit k pojmenování souboru zprávy.
 * V případě výskytu souboru v adresáři dojde k inkrementování čísla přípony.
 * Je-li předmět zprávy prázdný, tak se nastaví jméno 'unknown'.
 * @param msg textový řetězec obsahující staženou zprávu
 * @return string obsahující název souboru
 *
 * Při vytváření funkce bylo čerpáno z:
 * Zdroj: https://www.tutorialspoint.com/cpp_standard_library/cpp_regex_search.htm
 */
string getFileName(string msg);

/**
 * Funkce pro ukládání Message-ID staženách zpráv.
 * @param id Message-ID stažené zprávy
 *
 * Při vytváření funkce bylo čerpáno z:
 * Zdroj:   Stack Overflow
 * Dotaz:   https://stackoverflow.com/a/6296808
 * Odpověď: https://stackoverflow.com/a/6296808
 * Autor:   Rico
 * Autor:   https://stackoverflow.com/users/787716/rico
 * Datum: 9. června 2011
 */
void saveMsgId(string id);

/**
 * Funkce pro ukládání stažených zpráv do souboru.
 * @param fileName název souboru
 * @param msg textový řetězec obsahující staženou zprávu
 * @param msgCntr ukazatel na číselnou hodnotu obsahující počet stažených zpráv
 */
void saveMsg(string fileName, string msg, int &msgCntr);

/**
 * Funkce pro výpis informací o počtu stažených zpráv.
 * @param msgCntr číselná hodnota obsahující počet stažených zpráv
 */
void outputMsg(int msgCntr);

/**
 * Funkce pro zaslání příkazu QUIT na server.
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int quitMessage();

/**
 * Funkce pro ukončení spojení a navrácení return kódu.
 * @param returnCode return kód k navrácení
 * @return returnCode
 */
int closeBioAndEnd(int returnCode);

#endif