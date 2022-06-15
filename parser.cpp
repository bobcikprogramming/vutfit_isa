/**
 * Název:            main.hpp
 * Předmět:          Síťové aplikace a správa sítí
 * Instituce:        VUT FIT
 * Autor:            Pavel Bobčík
 * Login:            xbobci03
 * Vytvořeno:        16. října 2021
 */

#include "parser.hpp"

string server;
string port;
string outputDir;
string authFile;
bool deleteMsg = false;
bool readOnlyNew = false;
bool paramT = false;
bool paramS = false;
string certFile;
string certAddr;

int checkArg(int argc, char *argv[]) {
    int position = 1;
    argc = argc - 1;

    if (argc == 1) {
        if (strcmp(argv[1], HELP_LONG) != 0 || strcmp(argv[1], HELP_SHORT) != 0) {
            cout << HELP_MESSAGE;
            return -2;
        } else {
            cerr << "E: Vyplňte prosím všechny povinné údaje. Viz ./popcl --help\n";
            return -1;
        }
    }

    while (position <= argc) {
        switch (hashit(argv[position])) {
            case oP: {
                if (!port.empty()) {
                    cerr << "E: Chybový vstup - duplicitní přepínač " << argv[position] << "\n";
                    return -1;
                } else if (argc < (position + 1)) {
                    cerr << "E: Chybový vstup - chybné použití přepínače " << argv[position] << "\n";
                    return -1;
                }
                port = argv[position + 1];

                if (!regex_match(port, regex("^[0-9]*$"))) {
                    cerr << "E: Chybový vstup - neplatný port: " << port.c_str() << "\n";
                    return -1;
                }

                int checkPort = atoi(port.c_str());

                if (checkPort > MAX_PORT || checkPort < MIN_PORT) {
                    cerr << "E: Chybový vstup - neplatný port: " << port.c_str() << "\n";
                    return -1;
                }

                position += 2;
                break;
            }
            case oT:
                if (paramT) {
                    cerr << "E: Chybový vstup - duplicitní přepínač " << argv[position] << "\n";
                    return -1;
                } else if (paramS) {
                    cerr << "E: Chybový vstup - nelze kombinovat přepínače -T a -S\n";
                    return -1;
                }

                paramT = true;
                position += 1;
                break;
            case oS:
                if (paramS) {
                    cerr << "E: Chybový vstup - duplicitní přepínač " << argv[position] << "\n";
                    return -1;
                } else if (paramT) {
                    cerr << "E: Chybový vstup - nelze kombinovat přepínače -T a -S\n";
                    return -1;
                }

                paramS = true;
                position += 1;
                break;
            case oc:
                if (!certFile.empty()) {
                    cerr << "E: Chybový vstup - duplicitní přepínač " << argv[position] << "\n";
                    return -1;
                } else if (!paramT && !paramS) {
                    cerr << "E: Chybový vstup - chybné použití přepínače " << argv[position] << "\n";
                    return -1;
                } else if (argc < (position + 1)) {
                    cerr << "E: Chybový vstup - chybné použití přepínače " << argv[position] << "\n";
                    return -1;
                }

                certFile = argv[position + 1];
                position += 2;
                break;
            case oC:
                if (!certAddr.empty()) {
                    cerr << "E: Chybový vstup - duplicitní přepínač " << argv[position] << "\n";
                    return -1;
                } else if (!paramT && !paramS) {
                    cerr << "E: Chybový vstup - chybné použití přepínače " << argv[position] << "\n";
                    return -1;
                } else if (argc < (position + 1)) {
                    cerr << "E: Chybový vstup - chybné použití přepínače " << argv[position] << "\n";
                    return -1;
                }

                certAddr = argv[position + 1];
                position += 2;
                break;
            case oD:
                if (deleteMsg) {
                    cerr << "E: Chybový vstup - duplicitní přepínač " << argv[position] << "\n";
                    return -1;
                }

                deleteMsg = true;
                position += 1;
                break;
            case oN:
                if (readOnlyNew) {
                    cerr << "E: Chybový vstup - duplicitní přepínač " << argv[position] << "\n";
                    return -1;
                }

                readOnlyNew = true;
                position += 1;
                break;
            case oA:
                if (!authFile.empty()) {
                    cerr << "E: Chybový vstup - duplicitní přepínač " << argv[position] << "\n";
                    return -1;
                } else if (argc < (position + 1)) {
                    cerr << "E: Chybový vstup - chybné použití přepínače " << argv[position] << "\n";
                    return -1;
                }

                authFile = argv[position + 1];
                position += 2;
                break;
            case oO:
                if (!outputDir.empty()) {
                    cerr << "E: Chybový vstup - duplicitní přepínač " << argv[position] << "\n";
                    return -1;
                }

                outputDir = argv[position + 1];
                position += 2;
                break;
            case oServer:
                if (!server.empty()) {
                    cerr << "E: Chybový vstup - duplicitní zadání serveru\n";
                    return -1;
                }

                server = argv[position];
                if (checkIP() != 0) {
                    cerr << "E: Chybový formát IP adresy\n";
                    return -1;
                }
                position += 1;
                break;
        }
    }
    return 0;
}

string_code hashit(string const &inString) {
    if (inString == "-p") return oP;
    if (inString == "-T") return oT;
    if (inString == "-S") return oS;
    if (inString == "-c") return oc;
    if (inString == "-C") return oC;
    if (inString == "-d") return oD;
    if (inString == "-n") return oN;
    if (inString == "-a") return oA;
    if (inString == "-o")
        return oO;
    else
        return oServer;
}

int checkIP() {
    if (regex_match(server, regex("^([0-9]{1,3}.){3}[0-9]{1,3}$"))) {
        vector<string> octets;
        istringstream toSplit(server);
        string ip;
        while (getline(toSplit, ip, '.')) {
            octets.push_back(ip);
        }

        for (int i = 0; i < octets.size(); i++) {
            int octet = atoi(octets[i].c_str());
            if (octet > MAX_OCTET) {
                return -1;
            }
        }
    }
    return 0;
}

int mandatoryData() {
    if (server.empty() || authFile.empty() || outputDir.empty()) {
        cerr << "E: Vyplňte prosím všechny povinné údaje. Viz ./popcl --help\n";
        return -1;
    }
    return 0;
}

string getServer() {
    return server;
}

string getPort() {
    return port;
}

string getOutputDir() {
    return outputDir;
}

string getAuthFile() {
    return authFile;
}

bool getDeleteMsg() {
    return deleteMsg;
}

bool getReadOnlyNew() {
    return readOnlyNew;
}

bool getParamT() {
    return paramT;
}

bool getParamS() {
    return paramS;
}

string getCertFile() {
    return certFile;
}

string getCertAddr() {
    return certAddr;
}
