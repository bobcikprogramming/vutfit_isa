/**
 * Název:            main.cpp
 * Předmět:          Síťové aplikace a správa sítí
 * Instituce:        VUT FIT
 * Autor:            Pavel Bobčík
 * Login:            xbobci03
 * Vytvořeno:        3. října 2021
 */

#include "main.hpp"

BIO *bio, *sbio;
SSL *ssl;
SSL_CTX *ctx;

ofstream msgUIDs;

int main(int argc, char *argv[]) {
    int argCheck = checkArg(argc, argv);
    if (argCheck != 0 || mandatoryData() != 0) {
        if (argCheck == -2)
            // Zapnuto s přepínačem --help nebo -h. Program nekončí chybou, jedná se o platný vstup.
            return 0;
        return -1;
    }

    if (checkOutputDir() != 0)
        return -1;

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    int errCode;
    if (getParamT()) {
        if ((errCode = connectSSL()) != 0)
            return closeBioAndEnd(errCode);

    } else if (getParamS()) {
        if ((errCode = connectTLS()) != 0)
            return closeBioAndEnd(errCode);
    } else {
        if ((errCode = connectPOP3()) != 0)
            return closeBioAndEnd(errCode);
    }

    if (login() != 0)
        return closeBioAndEnd(-1);

    msgUIDs.open(UIDLIST_FILE, ios_base::app);

    int msgCntr = 0;
    if (getMails(msgCntr) != 0)
        return closeBioAndEnd(-1);

    outputMsg(msgCntr);
    msgUIDs.close();

    if (quitMessage() != 0)
        return closeBioAndEnd(-1);

    return closeBioAndEnd(0);
}

int checkOutputDir() {
    struct stat info;
    if (stat(getOutputDir().c_str(), &info) != 0) {
        mkdir(getOutputDir().c_str(), S_IRWXU);
        return checkOutputDir();
    } else if (info.st_mode & S_IFDIR) {
        return 0;
    } else {
        cerr << "E: Přepínač -o " << getOutputDir().c_str() << " neobsahuje platnou složku.\n";
        return -1;
    }
}

int connectPOP3() {
    bio = BIO_new_connect(getHostName(DEFAULT_PORT).c_str());
    if (bio == NULL) {
        cerr << "E: Nepodařilo se navázat spojení se serverem " << getServer().c_str() << ".\n";
        return -2;
    }

    if (BIO_do_connect(bio) <= 0) {
        cerr << "E: Nepodařilo se navázat spojení se serverem " << getServer().c_str() << ".\n";
        return -2;
    }

    char messageBuffer[BUFFER];
    if (readMessage(messageBuffer) != 0)
        return -1;

    if (strstr(messageBuffer, "+OK") == NULL) {
        cerr << "E: Nepodařilo se navázat spojení se serverem " << getServer().c_str() << ".\n";
        return -1;
    }
    memset(messageBuffer, 0, BUFFER);

    return 0;
}

int connectSSL() {
    if (getCtx() != 0)
        return -2;

    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    string serverAndPort = getHostName(DEFAULT_SSL_PORT);
    BIO_set_conn_hostname(bio, serverAndPort.c_str());

    if (BIO_do_connect(bio) <= 0) {
        cerr << "E: Nepodařilo se navázat spojení se serverem " << getServer().c_str() << ".\n";
        return -2;
    }

    if (checkCert() != 0)
        return -1;

    return 0;
}

int connectTLS() {
    sbio = NULL;
    int errCode;
    if ((errCode = connectPOP3()) != 0) {
        return errCode;
    }

    if (sendMessage(MESSAGE_STLS))
        return -1;

    char messageBuffer[BUFFER];
    if (readMessage(messageBuffer) != 0)
        return -1;

    if (strstr(messageBuffer, "+OK") == NULL) {
        cerr << "E: Nepodařilo se navázat spojení se serverem.\n";
        return -1;
    }

    memset(messageBuffer, 0, BUFFER);

    if (getCtx() != 0)
        return -1;

    sbio = BIO_new_ssl(ctx, 1);
    if ((bio = BIO_push(sbio, bio)) == NULL) {
        cerr << "E: Chyba při navazování šifrovaného spojení u TLS.\n";
    }
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    // SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (BIO_do_handshake(bio) > 0) {
        if (checkCert() != 0)
            return -1;
    } else {
        cerr << "E: Nastava chyba při handshake (TLS).\n";
        return -1;
    }

    return 0;
}

int getCtx() {
    ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_timeout(ctx, 15);
    if (!ctx) {
        cerr << "E: Chyby při vytváření spojení ssl (cxt).\n";
        return -1;
    }

    if (!getCertFile().empty() && !getCertAddr().empty()) {
        if (!SSL_CTX_load_verify_locations(ctx, getCertFile().c_str(), getCertAddr().c_str())) {
            cerr << "E: Chyba při ověřování souboru a složky s certifikáty.\n";
            return -1;
        }
    } else if (!getCertFile().empty()) {
        if (!SSL_CTX_load_verify_locations(ctx, getCertFile().c_str(), NULL)) {
            cerr << "E: Chyba při ověřování souboru s certifikáty.\n";
            return -1;
        }
    } else if (!getCertAddr().empty()) {
        if (!SSL_CTX_load_verify_locations(ctx, NULL, getCertAddr().c_str())) {
            cerr << "E: Chyba při ověřování složky s certifikáty.\n";
            return -1;
        }
    } else {
        SSL_CTX_set_default_verify_paths(ctx);
    }
    return 0;
}

int checkCert() {
    if (SSL_get_peer_certificate(ssl) == NULL) {
        cerr << "E: Nebyl předložen žádný certifikát nebo nebylo navázáno spojení.\n";
        return -1;
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        cerr << "E: Neúspěšné ověření certifikátu.";
        return -1;
    }
    return 0;
}

int sendMessage(string message) {
    if (BIO_write(bio, message.c_str(), message.length()) <= 0) {
        if (!BIO_should_retry(bio)) {
            cerr << "E: Spojení se serverem " << getServer().c_str() << " bylo ukončeno.\n";
            return -1;
        }
    }
    return 0;
}

int readMessage(char *messageBuffer) {
    memset(messageBuffer, 0, BUFFER);
    int x = BIO_read(bio, messageBuffer, (BUFFER - 1));
    if (x <= 0) {
        cerr << "E: Spojení se serverem " << getServer().c_str() << " bylo ukončeno.\n";
        return -1;
    }
    return 0;
}

string getHostName(string defaultPort) {
    return getServer() + ":" + (getPort().empty() ? defaultPort : getPort());
}

int login() {
    string user = "";
    string pass = "";

    if (getAuthInfo(user, pass) != 0)
        return -1;

    if (sendMessage(user) != 0)
        return -1;

    char messageBuffer[BUFFER];
    if (readMessage(messageBuffer) != 0)
        return -1;

    if (strstr(messageBuffer, "+OK") == NULL) {
        cerr << "E: Neplatné přihlašovací údaje.\n";
        return -1;
    }
    memset(messageBuffer, 0, BUFFER);

    if (sendMessage(pass) != 0)
        return -1;

    if (readMessage(messageBuffer) != 0)
        return -1;

    if (strstr(messageBuffer, "+OK") == NULL) {
        cerr << "Neplatné přihlašovací údaje.\n";
        return -1;
    }
    memset(messageBuffer, 0, BUFFER);

    return 0;
}

int getAuthInfo(string &user, string &pass) {
    ifstream MyReadFile(getAuthFile().c_str());
    string output;
    int line = 0;

    while (getline(MyReadFile, output)) {
        if (line == 0) {
            if (!regex_match(output, regex("^(username = ).*$"))) {
                cerr << "E: Chybný formát autentizačního souboru.\n + Pro více informací použijete ./popcl --help.\n";
                return -1;
            }
            output = regex_replace(output, regex("^(username = )"), "");
            user = MESSAGE_USER + output + MESSAGE_END;
        } else if (line == 1) {
            if (!regex_match(output, regex("^(password = ).*$"))) {
                cerr << "E: Chybný formát autentizačního souboru.\n + Pro více informací použijete ./popcl --help.\n";
                return -1;
            }
            output = regex_replace(output, regex("^(password = )"), "");
            pass = MESSAGE_PASS + output + MESSAGE_END;
        }
        line++;
    }

    if (line != 2) {
        cerr << "E: Chybný formát autentizačního souboru.\n + Pro více informací použijete ./popcl --help.\n";
        return -1;
    }

    MyReadFile.close();
    return 0;
}

int getMails(int &msgCntr) {
    int msgCnt = getMsgCount();
    if (msgCnt < 0)
        return -1;
    for (int i = 1; i <= msgCnt; i++) {
        string msg;
        if (downloadMsg(i, msg) != 0)
            return -1;

        string id = getMsgId(msg);
        if (id.empty())
            continue;

        if (getReadOnlyNew()) {
            if (!isNewMail(id))
                continue;
        }

        if (getDeleteMsg()) {
            if (setMsgToDelete(i) != 0)
                return -1;
        }

        string fileName = getFileName(msg);
        saveMsgId(id);
        saveMsg(fileName, msg, msgCntr);
    }
    return 0;
}

int getMsgCount() {
    if (sendMessage(MESSAGE_STAT) != 0)
        return -1;

    char messageBuffer[BUFFER];
    if (readMessage(messageBuffer) != 0)
        return -1;

    string msgCntString = messageBuffer;
    memset(messageBuffer, 0, BUFFER);
    msgCntString = regex_replace(msgCntString, regex("^[+](OK )"), "");
    msgCntString = regex_replace(msgCntString, regex(" [0-9]*(\n|\r\n|\r)"), "");
    return stoi(msgCntString);
}

int downloadMsg(int msgNumber, string &msg) {
    string retr = MESSAGE_RETR + to_string(msgNumber) + MESSAGE_END;
    if (sendMessage(retr) != 0)
        return -1;

    string endOfMessage = "\r\n.\r\n";
    size_t pos;
    string message;
    bool firstRead = true;
    char messageBuffer[BUFFER];
    do {
        if (readMessage(messageBuffer) != 0)
            return -1;

        regex rgxConfMsg("[+](OK).*(\r\n)");
        smatch matchConfMsg;
        string msgPart = messageBuffer;
        if (firstRead && !regex_search(msgPart, matchConfMsg, rgxConfMsg)) {
            cerr << "E: Neplatná zpráva u požadavku RETR.\n";
            return -1;
        }
        msgPart = regex_replace(msgPart, rgxConfMsg, "");

        message += msgPart;

        pos = message.find(endOfMessage);
        if (pos != string::npos) {
            message.replace(message.find("\r\n.\r\n"), sizeof("\r\n.\r\n") - 1, "\r\n");
        }
        firstRead = false;
    } while (pos == string::npos);
    memset(messageBuffer, 0, BUFFER);

    removeByteStuffing(message);

    msg = message;
    return 0;
}

void removeByteStuffing(string &msg) {
    string message = msg;
    string byteStuffing = "\r\n..";
    size_t byteStuff;
    byteStuff = message.find(byteStuffing);
    while (byteStuff != string::npos) {
        message.replace(message.find("\r\n.."), sizeof("\r\n..") - 1, "\r\n.");
        byteStuff = message.find(byteStuffing);
    }
    msg = message;
}

string getMsgId(string msg) {
    regex regex("(\n|\r|\r\n)(message-id:)[ ]?(<)(.*)(>)(\n|\r|\r\n)", icase);
    smatch match;
    if (regex_search(msg, match, regex)) {
        return match[4];
    } else {
        cerr << "E: Chyba při získávání Message-ID.\n";
        return "";
    }
}

bool isNewMail(string id) {
    bool newMail = true;
    ifstream uidRead(UIDLIST_FILE);
    string line;
    while (getline(uidRead, line)) {
        if (id == line) {
            newMail = false;
        }
    }
    return newMail;
}

int setMsgToDelete(int msgNumber) {
    string dele = MESSAGE_DELE + to_string(msgNumber) + MESSAGE_END;
    if (sendMessage(dele) != 0)
        return -1;

    char messageBuffer[BUFFER];
    if (readMessage(messageBuffer) != 0)
        return -1;

    if (strstr(messageBuffer, "+OK") == NULL) {
        cerr << "E: DELE: Neplatná zpráva.\n";
        return -1;
    }
    memset(messageBuffer, 0, BUFFER);

    return 0;
}

string getFileName(string msg) {
    smatch match;
    string fileName;
    if (regex_search(msg, match, regex("(\n|\r|\r\n)(subject: )(.*)(\n|\r|\r\n)", icase))) {
        fileName = match[3];
        replace(fileName.begin(), fileName.end(), ' ', '_');
        while (regex_search(fileName, match, regex("[^a-zA-Z0-9-_()]"))) {
            fileName = regex_replace(fileName, regex("[^a-zA-Z0-9-_()]"), "");
        }
        if (fileName.empty()) {
            fileName = "unknown";
        }
    } else {
        fileName = "unknown";
    }

    return fileName;
}

void saveMsgId(string id) {
    bool idSaved = false;
    string line;
    ifstream uidRead(UIDLIST_FILE);
    while (getline(uidRead, line)) {
        if (id == line) {
            idSaved = true;
        }
    }

    if (!idSaved) {
        msgUIDs << id << endl;
    }
}

void saveMsg(string fileName, string msg, int &msgCntr) {
    string filePath = getOutputDir() + "/" + fileName + ".txt";
    struct stat buf;
    int i = 2;
    while (stat(filePath.c_str(), &buf) != -1) {
        filePath = getOutputDir() + "/" + fileName + "(" + to_string(i) + ").txt";
        i++;
    }
    ofstream mailFile(filePath);
    mailFile << msg;
    mailFile.close();
    msgCntr++;
}

void outputMsg(int msgCntr) {
    if (getReadOnlyNew()) {
        if (msgCntr == 0) {
            cout << "Nemáte žádnou novou zprávu.\n";
        } else {
            cout << "Staženo nových zpráv: " << to_string(msgCntr) << ".\n";
        }
    } else {
        if (msgCntr == 0) {
            cout << "Nemáte žádnou zprávu.\n";
        } else {
            cout << "Staženo zpráv: " << to_string(msgCntr) << ".\n";
        }
    }
}

int quitMessage() {
    if (sendMessage(MESSAGE_QUIT) != 0)
        return -1;

    char messageBuffer[BUFFER];
    if (readMessage(messageBuffer) != 0)
        return -1;
    if (strstr(messageBuffer, "+OK") == NULL) {
        cerr << "Některé zprávy k smazání nebyly smazány.\n";
    }
    memset(messageBuffer, 0, BUFFER);

    return 0;
}

int closeBioAndEnd(int returnCode) {
    if (returnCode == -2) {
        if (getParamT()) {
            SSL_CTX_free(ctx);
        }
        return -1;
    } else {
        if (getParamT() || getParamS()) {
            SSL_CTX_free(ctx);
        }
        BIO_free_all(bio);
        return returnCode;
    }
}