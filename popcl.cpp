/*
 * Author: Filip Brna, xbrnaf00
 * Project: ISA Client POP3 with TLS
 * date: 19.10.2021
 */

// required header files
#include <iostream>
#include <string>
#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fstream>
#include <regex>
#include <chrono>
#include <thread>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

// global variables necessary especially when assigning arguments
string server_name;
string port_num;
string certfile;
string certaddr;
string auth_file;
string out_dir;
string username;
string password;
string messageID;
int NumberOfDownloads = 0;

bool p_bool = false;
bool T_bool = false;
bool S_bool = false;
bool c_bool = false;
bool C_bool = false;
bool d_bool = false;
bool n_bool = false;
bool a_bool = false;
bool o_bool = false;

/* DownloadEmails
function that opens a file and saves the message with the name of its message ID
has no return values
string Msg is a message from buffer (contains a response from the server)  */
void DownloadEmails(string Msg)
{
    // Check if only new messages will be downloaded
    if (!n_bool)
    {
        ofstream MyFile(out_dir + "/" + messageID); // open file for writting
        size_t tail = Msg.find("\r\n.\r\n");        // check if message contains tail
        if (tail != string::npos)
        {
            // Write to the file
            string MsgWithoutTail = Msg.substr(0, Msg.size() - 7); // remove tail
            MyFile << MsgWithoutTail;                              // write to file
            MyFile.close();
            NumberOfDownloads++;
        }
    }
    else // download all messages
    {
        ifstream ifile; // if file exist open it, if doesn't create it
        ifile.open(out_dir + "/" + messageID);
        if (!ifile)
        {
            ofstream MyFile(out_dir + "/" + messageID);
            size_t tail = Msg.find("\r\n.\r\n"); // check if message contains tail
            if (tail != string::npos)
                if (tail != string::npos)
                {
                    // Write to the file
                    string MsgWithoutTail = Msg.substr(0, Msg.size() - 7); // remove tail
                    MyFile << MsgWithoutTail;                              // write to file
                    MyFile.close();
                    NumberOfDownloads++;
                }
        }
        return;
    }
}
/*BioLibFunctions
function for sending commands to the server, saves a massageID from the server's email response
checking if no error occurred during communication
has no return values
BIO *bio structure for communication with the server
*/
void BioLibFunctions(BIO *bio)
{
    int len;
    char tmpbuf[1024];       // buffer for email response
    fill_n(tmpbuf, 1024, 0); // clear buffer

    BIO_puts(bio, ("USER " + username + "\r\n").c_str()); // send command for USER with username form authentification file
    len = BIO_read(bio, tmpbuf, 1024);                    // read response from server

    if (tmpbuf[0] == '-') // check if server response is not -ERR
    {
        cerr << "Error: user loggin \n";
        exit(EXIT_FAILURE);
    }
    fill_n(tmpbuf, 1024, 0); // clear buffer

    BIO_puts(bio, ("PASS " + password + "\r\n").c_str()); // send command for PASSWORD with password form authentification file
    len = BIO_read(bio, tmpbuf, 1024);                    // read response from server

    if (tmpbuf[0] == '-')
    {
        cerr << "Error: wrong password or username\n";
        exit(EXIT_FAILURE);
    }
    fill_n(tmpbuf, 1024, 0); // clear buffer

    BIO_puts(bio, "STAT\r\n");         // send command for STATS to get server information
    len = BIO_read(bio, tmpbuf, 1024); // read response from server

    if (tmpbuf[0] == '-')
    {
        cerr << "Error: due to STAT response\n";
        exit(EXIT_FAILURE);
    }
    else
    {
        int numberOfMails;                  // number of mails, earned from STAT command
        int octetsSize;                     // number of octets, earned from STAT command
        int octetsInMail;                   // number of octets, will be earned from RETR command
        smatch match;                       // regular experssion structure for matches
        string str_tmpbuf = string(tmpbuf); // response from server covnverted to string
        string Msg;
        regex_search(str_tmpbuf, match, regex("^(\\+OK )([0-9]+)( )([0-9]+)")); // regular expression checking and storing number of mail and its octet size
        numberOfMails = stoi(match.str(2));
        octetsSize = stoi(match.str(4));

        for (int i = 1; i < numberOfMails + 1; i++) // send command RETR for every email
        {
            Msg = "";
            fill_n(tmpbuf, 1024, 0);
            if (!d_bool) // if no delete argument is given
            {

                BIO_puts(bio, ("RETR " + to_string(i) + "\r\n").c_str()); // send command for RETRIVE SELECTED EMAIL
                usleep(10000);                                            // sleep, because of slower server response
                while (true)
                {
                    len = BIO_read(bio, tmpbuf, 1024); // read response from server
                    str_tmpbuf = string(tmpbuf).substr(0, 4);
                    if (str_tmpbuf == "-ERR")
                    {
                        cerr << "Error: server response\n";
                        exit(EXIT_FAILURE);
                    }

                    string str_tmpbuf = string(tmpbuf);
                    smatch match;

                    if (regex_search(str_tmpbuf, match, regex("(Message-[Ii][Dd]: \\<)(.+)\\>")) == true) // regular expression to get a value of Message-ID
                    {
                        messageID = match.str(2); // store value of Message-ID
                    }

                    if (str_tmpbuf.length() > len) // cut variable str_tmpbuf for corrcet working with server response
                    {
                        str_tmpbuf.erase(str_tmpbuf.end() - (str_tmpbuf.length() - len), str_tmpbuf.end());
                    }
                    Msg = Msg + str_tmpbuf;

                    size_t tail = (string(tmpbuf)).find("\r\n.\r\n");
                    if (tail != string::npos) // if tail was found Message is complete and
                    {                         // Msg is sended to download email function with the body of a file consisting of Msg
                        DownloadEmails(Msg.erase(0, Msg.find("\n") + 1));
                        break;
                    }
                    fill_n(tmpbuf, 1024, 0);
                }
            }
            else // delete argument is given
            {
                BIO_puts(bio, ("DELE " + to_string(i) + "\r\n").c_str()); // send command for DELETING SELECTED MESSAGE
                len = BIO_read(bio, tmpbuf, 1024);
                if (tmpbuf[0] == '-')
                {
                    cerr << "Error: server response\n";
                    exit(EXIT_FAILURE);
                }
                if (i == numberOfMails)
                {
                    cout << numberOfMails << " - email/s deleted\n";
                }
            }
        }
        if (d_bool && (numberOfMails == 0))
        {
            cout << "0 - emails deleted\n";
        }
    }
    fill_n(tmpbuf, 1024, 0);

    BIO_puts(bio, "QUIT\r\n"); // send command for QUIT SERVER CONNECTION
    len = BIO_read(bio, tmpbuf, 1024);

    if (tmpbuf[0] == '-')
    {
        cerr << "Error: Quit server\n";
        exit(EXIT_FAILURE);
    }
    fill_n(tmpbuf, 1024, 0);

    BIO_free(bio);
}

/*SecureConnection
function for secured connection to server when -T argument is given
checking certifications if they were given, if not set default certificates
has no return values
*/
void SecureConnection()
{
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method()); // structure to hold the SSL information
    SSL *ssl;                                           // SSL connection structure
    BIO *bio;                                           // structure BIO to handle communication
    int len;
    char tmpbuf[1024];
    fill_n(tmpbuf, 1024, 0);
    if (c_bool && certfile != "" && C_bool && certaddr != "") // if -c -C with names of files/directories was given
    {
        if (!SSL_CTX_load_verify_locations(ctx, certfile.c_str(), NULL)) // load certificates from files
        {
            cerr << "Error: with certfile\n";
            exit(EXIT_FAILURE);
        }
        if (!SSL_CTX_load_verify_locations(ctx, NULL, certaddr.c_str())) // load certificates from directory
        {
            cerr << "Error: with certaddr\n";
            exit(EXIT_FAILURE);
        }
    }

    else if (c_bool && certfile != "") // if -c with name of file was given
    {
        if (!SSL_CTX_load_verify_locations(ctx, certfile.c_str(), NULL)) // load certificates from files
        {
            cerr << "Error: with certfile\n";
            exit(EXIT_FAILURE);
        }
    }
    else if (C_bool && certaddr != "") // if -C with name of directory was given
    {
        if (!SSL_CTX_load_verify_locations(ctx, NULL, certaddr.c_str())) // load certificates from directory
        {
            cerr << "Error: with certaddr\n";
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        SSL_CTX_set_default_verify_paths(ctx); // if -T was given without -c -C set default certificates
    }

    bio = BIO_new_ssl_connect(ctx); // Setting up the BIO object
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if (!p_bool) // if -p and number of port argument wasn't given
    {
        BIO_set_conn_hostname(bio, (server_name + ":995").c_str()); // Opening a secure connection
    }
    else // if -p and number of port argument was given
    {
        BIO_set_conn_hostname(bio, ((server_name + ":" + port_num).c_str())); // Opening a secure connection
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) // Checking if a certificate is valid
    {
        cerr << "Error: failed verification\n";
        exit(EXIT_FAILURE);
    }
    // Verify the connection opened and perform the handshake
    if (BIO_do_connect(bio) <= 0)
    {
        cerr << "Error: failed connection\n";
        exit(EXIT_FAILURE);
    }
    len = BIO_read(bio, tmpbuf, 1024); // read response from server
    fill_n(tmpbuf, 1024, 0);
    BioLibFunctions(bio);
}

/*NoSecureConnection
function for not secured connection to server when -T argument wasn't given
checking certifications (when -S argument) if they were given, if not set default certificates
has no return values
*/
void NoSecureConnection()
{
    SSL_library_init();
    SSL_load_error_strings(); // Initializing OpenSSL
    OpenSSL_add_all_algorithms();
    SSL *ssl;                                           // SSL connection structure
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method()); // structure to hold the SSL information
    BIO *bio, *bio2;                                    // structure BIO to handle communication
    int len;
    char tmpbuf[1024];
    fill_n(tmpbuf, 1024, 0);

    ERR_load_crypto_strings();

    if (!p_bool) // if -p and number of port argument wasn't given
    {
        bio = BIO_new_connect((server_name + ":110").c_str()); // Creating and opening a connection
    }
    else // if -p and number of port argument was given
    {
        bio = BIO_new_connect((server_name + ":" + port_num).c_str()); // Creating and opening a connection
    }
    len = BIO_read(bio, tmpbuf, 1024); // read response from server

    if (S_bool) // if -S argument was given communication need to be switched from unsecured to secured
    {
        BIO_puts(bio, "STLS\r\n"); // send command for SECURED CONNECTION
        len = BIO_read(bio, tmpbuf, 1024);
        if (tmpbuf[0] == '-')
        {
            cerr << "Error: STLS connection\n"; //
            exit(EXIT_FAILURE);
        }
    }

    if (BIO_do_connect(bio) <= 0) // must be made to verify that the connection was successful
    {
        cerr << "Error: not connected to server\n";
        exit(EXIT_FAILURE);
    }
    fill_n(tmpbuf, 1024, 0);

    if (S_bool) // if -S argument was given communication need to check certificates
    {
        if (c_bool && certfile != "" && C_bool && certaddr != "") // if -c -C with names of files/directories was given
        {
            if (!SSL_CTX_load_verify_locations(ctx, certfile.c_str(), NULL)) // load certificates from files
            {
                cerr << "Error: with certfile\n";
                exit(EXIT_FAILURE);
            }
            if (!SSL_CTX_load_verify_locations(ctx, NULL, certaddr.c_str())) // load certificates from directory
            {
                cerr << "Error: with certaddr\n";
                exit(EXIT_FAILURE);
            }
        }

        else if (c_bool && certfile != "") // if -c with name of file was given
        {
            if (!SSL_CTX_load_verify_locations(ctx, certfile.c_str(), NULL)) // load certificates from files
            {
                cerr << "Error: with certfile\n";
                exit(EXIT_FAILURE);
            }
        }
        else if (C_bool && certaddr != "") // if -C with name of directory was given
        {
            if (!SSL_CTX_load_verify_locations(ctx, NULL, certaddr.c_str())) // load certificates from director
            {
                cerr << "Error: with certaddr\n";
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            SSL_CTX_set_default_verify_paths(ctx); // if -T was given without -c -C set default certificates
        }

        //  ------------ BEGIN   ----------------
        //  https://stackoverflow.com/questions/49132242/openssl-promote-insecure-bio-to-secure-one
        // part was inspirated by stackoverflow:
        // question : OpenSSL: Promote insecure BIO to secure one
        // answer : answered Mar 6 '18 at 13:54 by Martin Prikryl
        if ((bio2 = BIO_new_ssl(ctx, 1)) == NULL)
        {
            BIO_free(bio);
        }
        if ((bio = BIO_push(bio2, bio)) == NULL)
        {
            BIO_free(bio);
        }
        // ------------- END -----------------

        BIO_get_ssl(bio, &ssl); // Setting up the BIO object
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        if (SSL_get_verify_result(ssl) != X509_V_OK) // verify certificates
        {
            cerr << "Error: failed verification\n";
            exit(EXIT_FAILURE);
        }
    }

    BioLibFunctions(bio);
}

/*CheckNextArg
function whose purpose is to check the next parameter to be entered when starting the program
int argc, char **argv - program argument, int i - actual position on argumnets check 
string return value contain next argument from program arguments
*/
string CheckNextArg(int argc, char **argv, int i)
{
    string next_arg;
    try
    {
        next_arg = string(argv[i + 1]); // the variable located after the current argument is stored in the variable
    }
    catch (exception) // if there is not any next argument it's invalid arguments error
    {
        cerr << "Error invalid arguments\n";
        exit(EXIT_FAILURE);
    }

    // if the wrong parameter is specified after the argument, the function ends with an error message
    if (next_arg == "-T" || next_arg == "-S" || next_arg == "-p" || next_arg == "-C" ||
        next_arg == "-d" || next_arg == "-n" || next_arg == "-a" || next_arg == "-o" || next_arg == "-c")
    {
        cerr << "Error invalid arguments\n";
        exit(EXIT_FAILURE);
    }
    return next_arg; // returns a string containing, for example, -p port number (-p <port_number>) or -c return name of certification file (-c <certfile>), ...
}

/*ProcessArgs
function whose purpose is to check check arguments of the program
also setting global variables
int argc, char **argv - program argument
no return value
*/
void ProcessArgs(int argc, char **argv)
{
    server_name = string(argv[1]); // required argument containing server name
    string argument;
    for (int i = 1; i < argc; i++) // loop for checking and setting arguments one by one
    {
        argument = string(argv[i]);
        if (argument == "-p") // if the -p argument is specified, it is followed by the port number
        {
            p_bool = true;
            port_num = CheckNextArg(argc, argv, i); // store to variable port value
            i++;
        }
        else if (argument == "-T") // if specified, the communication is secured
        {
            T_bool = true;
        }
        else if (argument == "-S")
        {
            S_bool = true; // if specified, the communication is not secured at the beginnin but after STLS command is switched to secured
        }
        else if (argument == "-c" && (T_bool || S_bool)) // -c argument can only be combined with -T or -S
        {
            c_bool = true;
            certfile = CheckNextArg(argc, argv, i); // store to variable certificate file
            i++;
        }
        else if (argument == "-C" && (T_bool || S_bool)) // -C argument can only be combined with -T or -S
        {
            C_bool = true;
            certaddr = CheckNextArg(argc, argv, i); // store to variable directory name where are certificates located
            i++;
        }
        else if (argument == "-d") // command for emails deleting
        {
            d_bool = true;
        }
        else if (argument == "-n") // command for downloading just new emails
        {
            n_bool = true;
        }
        else if (argument == "-a") // required argument followed by the name of the authentication file
        {
            a_bool = true;
            auth_file = CheckNextArg(argc, argv, i);
            i++;
        }
        else if (argument == "-o") // required argument followed by the name of the output directory
        {
            o_bool = true;
            out_dir = CheckNextArg(argc, argv, i);
            i++;
        }
        else if ((argument == "-c" || argument == "-C") && (!T_bool || !S_bool)) // -c and -C can be used just with -T or -S
        {
            cerr << "Error: wrong program arguments\n";
            exit(EXIT_FAILURE);
        }
    }

    // check if required arguments were entered
    if (!a_bool || !o_bool || server_name == "" || auth_file == "" || out_dir == "")
    {
        cerr << "Error: arguments missing\n";
        exit(EXIT_FAILURE);
    }
}

/*CheckoutDirAndFile
A function to check whether the specified directories / files exist,
find out and store the name and password from the authentication file
no return value
*/
void CheckoutDirAndFile()
{
    struct stat buffer;
    if (stat(out_dir.c_str(), &buffer) != 0) // directory doesn't exist
    {
        cerr << "Error : " << out_dir << " directory doesn't exist\n";
        exit(EXIT_FAILURE);
    }
    if (stat(auth_file.c_str(), &buffer) != 0) // authentification file doesn't exist
    {
        cerr << "Error : " << auth_file << " auth_file doesn't exist\n";
        exit(EXIT_FAILURE);
    }
    else // authentification file exist
    {
        ifstream file(auth_file);
        if (file.is_open())
        {
            string line;
            int cnt = 0;
            while (getline(file, line)) // is read line by line from the authentication file, then the file format is checked
            {
                if (cnt == 0 and (regex_match(line.c_str(), regex("^(username = )([^\\s]+)$"))))
                {
                    string tmp_line = line.c_str();
                    username = tmp_line.substr(11, -1); // if the file format is correct, the name is stored in the variable
                }
                else if (cnt == 1 and (regex_match(line.c_str(), regex("^(password = )([^\\s]+)$"))))
                {
                    string tmp_line = line.c_str();
                    password = tmp_line.substr(11, -1); // if the file format is correct, the password is stored in the variable
                }
                else
                {
                    cerr << "Error : with auth_file, incorrect format\n";
                    exit(EXIT_FAILURE);
                }
                cnt++;
            }
            if (strcmp(line.c_str(), "") == 0)
            {
                cerr << "Error : with auth_file, incorrect format\n";
                exit(EXIT_FAILURE);
            }
            file.close(); // closing file
        }
    }
}

/*main
a function that calls functions such as ProcessArgs, CheckoutDirAndFiles and according to specification secure or no secure connection function
int return value
*/
int main(int argc, char **argv)
{

    ProcessArgs(argc, argv);
    CheckoutDirAndFile();
    if (T_bool)
    {
        SecureConnection();
    }
    else
    {
        NoSecureConnection();
    }
    if (!n_bool && !d_bool)
    {
        cout << NumberOfDownloads << " - email/s downloaded\n";
    }
    else if (!d_bool)
    {
        cout << NumberOfDownloads << " - new email/s downloaded\n";
    }

    return 0;
}