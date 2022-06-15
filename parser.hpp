/**
 * Název:            main.hpp
 * Předmět:          Síťové aplikace a správa sítí
 * Instituce:        VUT FIT
 * Autor:            Pavel Bobčík
 * Login:            xbobci03
 * Vytvořeno:        16. října 2021
 */

#ifndef PARSER
#define PARSER

#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

#define MAX_OCTET 255
#define MAX_PORT 65535
#define MIN_PORT 0
#define HELP_LONG "--help"
#define HELP_SHORT "-h"

#define HELP_MESSAGE                                                                                                                \
    "/******************************/\n"                                                                                            \
    " * Nápověda k použití programu:\n"                                                                                         \
    " * +  Použití: ./popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>\n" \
    " * +  Povinné údaje:\n"                                                                                                      \
    " *  +    <server>       : IP adresa nebo doménové jméno požadovaného zdroje\n"                                            \
    " *  +    -a <auth_file> : soubor obsahující autentizaci uživatele\n"                                                        \
    " *                      : obsah souboru:\n"                                                                                    \
    " *                         username = <jméno>\n"                                                                              \
    " *                         password = <heslo>\n"                                                                               \
    " *  +    -o <out_dir>   : výstupní adresář pro ukládání stažených zprávy\n"                                          \
    " * +  Volitelné údaje:\n"                                                                                                   \
    " *  +    -p <port>      : číslo portu\n"                                                                                     \
    " *  +    -T             : varianta SSL\n"                                                                                      \
    " *  +    -S             : varianta TLS\n"                                                                                      \
    " *  +    -c <certfile>  : soubor s certifikáty\n"                                                                             \
    " *  +    -C <certaddr>  : adresář s certifikáty\n"                                                                          \
    " *  +    -d             : příkaz pro smazání zprávy na serveru\n"                                                         \
    " *  +    -n             : stahování pouze nových zpráv\n";

/**
 * Enumeration pro převod textových řetězců, representující vstupní argumenty, na číselné hodnoty.
 *
 * Při vytváření switch bylo čerpáno z:
 * Zdroj:   Stack Overflow
 * Dotaz:   https://stackoverflow.com/q/650162
 * Odpověď: https://stackoverflow.com/a/650307
 * Autor:   D.Shawley
 * Autor:   https://stackoverflow.com/users/41747/d-shawley
 * Datum:   16. března 2009
 */
enum string_code {
    oP,
    oT,
    oS,
    oc,
    oC,
    oD,
    oN,
    oA,
    oO,
    oServer
};

/**
 * Funkce pro kontrolu argumentů na vstupu.
 * @param argc celkový počet argumentů
 * @param argv ukazatel na list obsahující argumenty
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 *
 * Při vytváření switch bylo čerpáno z:
 * Zdroj:   Stack Overflow
 * Dotaz:   https://stackoverflow.com/q/650162
 * Odpověď: https://stackoverflow.com/a/650307
 * Autor:   D.Shawley
 * Autor:   https://stackoverflow.com/users/41747/d-shawley
 * Datum:   16. března 2009
 */
int checkArg(int argc, char* argv[]);

/**
 * Funkce pro převod vstupních argumentů v textové podobě do číselné hodnoty (pomocí enum) u switch.
 *
 * Při vytváření switch bylo čerpáno z:
 * Zdroj:   Stack Overflow
 * Dotaz:   https://stackoverflow.com/q/650162
 * Odpověď: https://stackoverflow.com/a/650307
 * Autor:   D.Shawley
 * Autor:   https://stackoverflow.com/users/41747/d-shawley
 * Datum:   16. března 2009
 */
string_code hashit(string const& inString);

/**
 * Funkce pro kontrolu IP adresy
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 *
 * Při vytváření funkce bylo čerpáno z:
 * Zdroj:   Stack Overflow
 * Dotaz:   https://stackoverflow.com/q/5167625
 * Odpověď: https://stackoverflow.com/a/5167799
 * Autor:   Martin Stone
 * Autor:   https://stackoverflow.com/users/44615/martin-stone
 * Datum:   2. března 2011
 */
int checkIP();

/**
 * Funkce pro kontrolu, zdali byly všechny povinné údaje vyplněny
 * @return int o hodnotě 0/-1 podle toho, zdali operace proběhla úspěšné/neúspěšně
 */
int mandatoryData();

/**
 * Getter pro název serveru/IP.
 * @return název serveru/IP
 */
string getServer();

/**
 * Getter pro port
 * @return port
 */
string getPort();

/**
 * Getter pro výstupní adresář
 * @return výstupní adresář
 */
string getOutputDir();

/**
 * Getter pro autorizační soubor
 * @return autorizační soubor
 */
string getAuthFile();

/**
 * Getter pro boolean hodnotu, zdali se mají smazat stažené zprávy
 * @return boolean hodnotu, zdali se mají smazat stažené zprávy
 */
bool getDeleteMsg();

/**
 * Getter pro boolean hodnotu, zdali se mají stáhnout pouze nové zprávy
 * @return boolean hodnotu, zdali se mají stáhnout pouze nové zprávy
 */
bool getReadOnlyNew();

/**
 * Getter pro boolean hodnotu, zdali se jedná o SSL spojení
 * @return boolean hodnotu, zdali se jedná o SSL spojení
 */
bool getParamT();

/**
 * Getter pro boolean hodnotu, zdali se jedná o TLS spojení
 * @return boolean hodnotu, zdali se jedná o TLS spojení
 */
bool getParamS();

/**
 * Getter pro soubor s certifikáty
 * @return soubor s certifikáty
 */
string getCertFile();

/**
 * Getter pro adresář s certifikáty
 * @return adresář s certifikáty
 */
string getCertAddr();

#endif