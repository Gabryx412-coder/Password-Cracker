#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <openssl/md5.h>
#include <algorithm>

using namespace std;
using namespace chrono;

// **Classe per calcolo MD5 e gestione cache**
class MD5Hasher {
private:
    unordered_map<string, string> md5Cache;

public:
    string calculateMD5(const string& input) {
        if (md5Cache.find(input) != md5Cache.end()) {
            return md5Cache[input];
        }

        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5((unsigned char*)input.c_str(), input.size(), (unsigned char*)&digest);
        char md5String[33];
        for (int i = 0; i < 16; i++) {
            sprintf(&md5String[i * 2], "%02x", (unsigned int)digest[i]);
        }

        string hashStr(md5String);
        md5Cache[input] = hashStr; // Salva nella cache
        return hashStr;
    }
};

// **Classe per generazione combinazioni ottimizzata con iteratori**
class CombinationGenerator {
private:
    string chars;
    int maxLength;
    vector<int> indices;

public:
    CombinationGenerator(const string& chars, int maxLength) 
        : chars(chars), maxLength(maxLength), indices(maxLength, 0) {}

    bool nextCombination(string& combination) {
        combination.clear();
        for (int idx : indices) {
            combination += chars[idx];
        }

        for (int i = maxLength - 1; i >= 0; --i) {
            if (indices[i] < chars.size() - 1) {
                ++indices[i];
                return true;
            } else {
                indices[i] = 0;
            }
        }
        return false;
    }
};

// **Classe per gestire i vari tipi di attacco**
class PasswordCracker {
private:
    MD5Hasher hasher;
    string targetHash;
    atomic<bool> found;
    mutex outputMutex;
    int maxLength;
    int numThreads;
    int timeout;
    vector<thread> threads;

    // Funzione per brute-force con thread
    void bruteForceWorker(int threadID, int& attempts, steady_clock::time_point start) {
        CombinationGenerator generator("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#", maxLength);
        string candidate;
        
        while (!found && generator.nextCombination(candidate)) {
            if (threadID > 0 && candidate[0] != 'a' + (threadID % 26)) continue; // Ogni thread inizia con una lettera diversa

            attempts++;
            if (hasher.calculateMD5(candidate) == targetHash) {
                lock_guard<mutex> lock(outputMutex);
                cout << "Password trovata: " << candidate << endl;
                found = true;
                return;
            }

            if (attempts % 1000 == 0) { 
                lock_guard<mutex> lock(outputMutex);
                cout << "Tentativi da thread " << threadID << ": " << candidate << endl;
            }

            // Timeout
            if (duration_cast<seconds>(steady_clock::now() - start).count() >= timeout) {
                lock_guard<mutex> lock(outputMutex);
                cout << "Timeout raggiunto da thread " << threadID << endl;
                return;
            }
        }
    }

    // Funzione di caricamento del dizionario con ottimizzazione
    void loadAndSortDictionary(const string& dictionaryPath, vector<string>& words) {
        ifstream file(dictionaryPath);
        if (!file.is_open()) {
            cerr << "Errore: Impossibile aprire il dizionario." << endl;
            return;
        }

        string word;
        while (file >> word) {
            if (word.length() <= maxLength) {
                words.push_back(word);
            }
        }

        sort(words.begin(), words.end()); // Ordina per una ricerca più efficiente
    }

public:
    PasswordCracker(const string& hash, int length, int threads, int time_limit) 
        : targetHash(hash), maxLength(length), numThreads(threads), timeout(time_limit) {
        found = false;
    }

    // Funzione per avviare il brute-force multi-thread
    void startBruteForceAttack() {
        int totalAttempts = 0;
        auto start = steady_clock::now();

        for (int i = 0; i < numThreads; ++i) {
            threads.push_back(thread(&PasswordCracker::bruteForceWorker, this, i, ref(totalAttempts), start));
        }

        for (auto& th : threads) {
            th.join();
        }

        if (!found) {
            cout << "Password non trovata con brute-force." << endl;
        }
        cout << "Tentativi totali: " << totalAttempts << endl;
    }

    // Funzione di attacco con dizionario ottimizzata
    void startDictionaryAttack(const string& dictionaryPath) {
        vector<string> words;
        loadAndSortDictionary(dictionaryPath, words);

        int attempts = 0;
        auto start = steady_clock::now();

        for (const string& word : words) {
            attempts++;
            if (hasher.calculateMD5(word) == targetHash) {
                cout << "Password trovata nel dizionario: " << word << endl;
                found = true;
                break;
            }

            if (attempts % 100 == 0) {
                lock_guard<mutex> lock(outputMutex);
                cout << "Tentativo dizionario: " << word << endl;
            }

            if (duration_cast<seconds>(steady_clock::now() - start).count() >= timeout) {
                cout << "Timeout raggiunto durante attacco dizionario." << endl;
                break;
            }
        }

        if (!found) {
            cout << "Password non trovata nel dizionario." << endl;
        }
        cout << "Tentativi totali dizionario: " << attempts << endl;
    }
};

// **Funzione per input e avvio**
void getUserInputAndStart() {
    string targetHash;
    int attackMode;
    int maxLength;
    string dictionaryPath;
    int numThreads;
    int timeout;

    cout << "Inserisci l'hash MD5 della password: ";
    cin >> targetHash;

    cout << "Scegli modalità di attacco (1 = Forza Bruta, 2 = Dizionario): ";
    cin >> attackMode;

    cout << "Imposta un timeout (in secondi): ";
    cin >> timeout;

    if (attackMode == 1) {
        cout << "Inserisci la lunghezza massima della password: ";
        cin >> maxLength;
        cout << "Inserisci il numero di thread (consigliato 4-8): ";
        cin >> numThreads;

        PasswordCracker cracker(targetHash, maxLength, numThreads, timeout);
        cracker.startBruteForceAttack();
    } else if (attackMode == 2) {
        cout << "Inserisci il percorso del file del dizionario: ";
        cin >> dictionaryPath;

        PasswordCracker cracker(targetHash, 0, 1, timeout);
        cracker.startDictionaryAttack(dictionaryPath);
    } else {
        cout << "Modalità di attacco non valida." << endl;
    }
}

// **Funzione principale**
int main() {
    getUserInputAndStart();
    return 0;
}
