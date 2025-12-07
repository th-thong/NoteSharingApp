#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H
#include <string>
using namespace std;

class AuthManager(){
    public:
        AuthManager();
        void registerUser(string username, string password, string pubKey);
        string loginUser(string username, string password);
        string validateToken(string token);
        string getUserPublicKey(std::string username)

}

#endif