// // //
// // // Created by Vladimir on 20.06.20.
// // //

// #include "Utils.h"
// #include <iostream>
// #include <regex>
// #include <random>
// #include <sstream>
// #include <clang/AST/CommentLexer.h>

// #include <variant>


// using namespace Utils;

// // std::string Utils::randomString(std::string::size_type Length) {

// //     static auto &chrs = "0123456789"
// //                         "abcdefghijklmnopqrstuvwxyz"
// //                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ_";


// // thread_local static std::mt19937 rg{std::random_device{}()};
// //     thread_local static std::ranlux48_base rg{std::random_device{}()};
// //     thread_local static std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);


// //     std::string s;

// //     s.reserve(Length);

// //     while (Length--)
// //         s += chrs[pick(rg)];

// //     return s;
// // }

// // std::string Utils::randomString(std::string::size_type Length) {
// //     static auto &chrs = "0123456789"
// //                         "abcdefghijklmnopqrstuvwxyz"
// //                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ_";

// //     // Create a new random device each time the function is called
// //     std::random_device rd;
// //     // Use a bernoulli distribution to decide which random number generator to use
// //     std::bernoulli_distribution dist(0.5); // 50% chance for each generator
// //     bool useRanlux48 = dist(rd); // Randomly choose between ranlux48_base and mt19937

// //     if (useRanlux48) {
// //         std::ranlux48_base rg(rd());
// //         std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

// //         std::string s;
// //         s.reserve(Length);

// //         while (Length--)
// //             s += chrs[pick(rg)];

// //         return s;
// //     } else {
// //         std::mt19937 rg(rd());
// //         std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

// //         std::string s;
// //         s.reserve(Length);

// //         while (Length--)
// //             s += chrs[pick(rg)];

// //         return s;
// //     }
// // }


// std::string Utils::randomString(std::string::size_type Length) {
//     static auto &chrs = "0123456789"
//                         "abcdefghijklmnopqrstuvwxyz"
//                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ_";

//     // Create a new random device each time the function is called
//     std::random_device rd;
//     // Use a bernoulli distribution to decide which random number generator to use
//     std::bernoulli_distribution dist(0.5); // 50% chance for each generator
//     bool useRanlux48 = dist(rd); // Randomly choose between ranlux48_base and mt19937

//     if (useRanlux48) {
//         std::ranlux48_base rg(rd());
//         std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

//         std::string s;
//         s.reserve(Length);

//         while (Length--)
//             s += chrs[pick(rg)];

//         std::cout << "Generated random string using ranlux48_base\n";

//         return s;
//     } else {
//         std::mt19937 rg(rd());
//         std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

//         std::string s;
//         s.reserve(Length);

//         while (Length--)
//             s += chrs[pick(rg)];

//         std::cout << "Generated random string using mt19937\n";

//         return s;
//     }
// }


// std::string Utils::translateStringToIdentifier(const std::string &StrLiteral) {

//     std::string NewIdentifier = std::regex_replace(StrLiteral, std::regex("[^A-Za-z]"), "9");
//     return "mxt_" + NewIdentifier.substr(0, 6) + '_' + randomString(15) + "enu";
// }


// void Utils::cleanParameter(std::string &Argument) {

//     auto Index = Argument.find_first_of('\"');

//     Argument.erase(Argument.begin(), Argument.begin() + Index + 1);

//     if (Argument.back() == '\"') {
//         Argument.pop_back();
//     }
// }


// std::string
// Utils::generateVariableDeclaration(const std::string &StringIdentifier, const std::string &StringValue, std::string StringType) {

//     std::stringstream Result;

//     //Result << "\n#ifdef _UNICODE\n\twchar_t\n";
//     //Result << "#else\n\tchar\n#endif\n\t";
//     if(!StringType.empty()){
//         auto pos = StringType.find('*');
//         if (pos != std::string::npos)
//             StringType.erase(pos);

//         Result << StringType << " " << StringIdentifier;
//         /*if (StringType.find("char") != std::string::npos && StringType.find("*") == std::string::npos) {
//         }*/
//         Result << "[]";

//         Result << " = {";
//     } else {
//         llvm::outs() << StringValue <<  " Oups\n";

//         Result << "TCHAR " << StringIdentifier << "[] = {";
//     }

//     auto CleanString = std::string(StringValue);
//     cleanParameter(CleanString);
//     for (std::string::iterator it = CleanString.begin(); it != CleanString.end(); it++) {

//         if (*it == '\'') {
//             Result << "'\\" << *it << "'";
//         } else if (*it == '\\') {
//             Result << "'\\\\'";
//         } else if (*it == '\n') {
//             Result << "'\\n'";
//         } else if (*it != 0) {
//             int nb = (int)*it & 0xff;
//             Result << "'\\x" << std::hex << nb << "'";
//         } else {
//             continue;
//         }

//         uint32_t offset = 1;
//         if (it + offset != CleanString.end()) {
//             Result << ",";
//         }
//     }

//     if (*Result.str().end() == ',')
//         Result << "0};\n";
//     else
//         Result << ",0};\n";
//     return std::regex_replace(Result.str(), std::regex(",,"), ",");
// }











///https://blog.scrt.ch/2020/07/15/engineering-antivirus-evasion-part-ii/
///

#include "Utils.h"
#include <iostream>
#include <regex>
#include <random>
#include <sstream>
#include <clang/AST/CommentLexer.h>

#include <variant>
// #include "xoroshiro128Plus.h" // Include the Xoroshiro128+ header file



using namespace Utils;




std::pair<std::string, RandomAlgorithm> Utils::randomString(std::string::size_type Length) {
    static auto &chrs = "0123456789"
                        "abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ_";

    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 2); // 0: ranlux48_base, 1: mt19937, 2: minstd_rand
    int choice = dist(rd);

    if (choice == 0) {
        std::ranlux48_base rg(rd());
        std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

        std::string s;
        s.reserve(Length);

        while (Length--)
            s += chrs[pick(rg)];

        return {s, RandomAlgorithm::Ranlux48};
    } else if (choice == 1) {
        std::mt19937 rg(rd());
        std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

        std::string s;
        s.reserve(Length);

        while (Length--)
            s += chrs[pick(rg)];

        return {s, RandomAlgorithm::Mt19937};
    } else {
        std::minstd_rand rg(rd());
        std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

        std::string s;
        s.reserve(Length);

        while (Length--)
            s += chrs[pick(rg)];

        return {s, RandomAlgorithm::MinstdRand};
    }
}

std::string Utils::translateStringToIdentifier(const std::string &StrLiteral) {
    std::string NewIdentifier = std::regex_replace(StrLiteral, std::regex("[^A-Za-z]"), "9");
    auto randomResult = randomString(15);
    std::string algorithmCodeName;

    if (randomResult.second == RandomAlgorithm::Ranlux48) {
        algorithmCodeName = "R";
    } else if (randomResult.second == RandomAlgorithm::Mt19937) {
        algorithmCodeName = "M";
    } else {
        algorithmCodeName = "S";
    }

    return "mxt_" + NewIdentifier.substr(0, 6) + '_' + algorithmCodeName + '_' + randomResult.first + "enu";
}



void Utils::cleanParameter(std::string &Argument) {

    auto Index = Argument.find_first_of('\"');

    Argument.erase(Argument.begin(), Argument.begin() + Index + 1);

    if (Argument.back() == '\"') {
        Argument.pop_back();
    }
}


std::string
Utils::generateVariableDeclaration(const std::string &StringIdentifier, const std::string &StringValue, std::string StringType) {

    std::stringstream Result;

    //Result << "\n#ifdef _UNICODE\n\twchar_t\n";
    //Result << "#else\n\tchar\n#endif\n\t";
    if(!StringType.empty()){
        auto pos = StringType.find('*');
        if (pos != std::string::npos)
            StringType.erase(pos);

        Result << StringType << " " << StringIdentifier;
        /*if (StringType.find("char") != std::string::npos && StringType.find("*") == std::string::npos) {
        }*/
        Result << "[]";

        Result << " = {";
    } else {
        llvm::outs() << StringValue <<  " Oups\n";

        Result << "TCHAR " << StringIdentifier << "[] = {";
    }

    auto CleanString = std::string(StringValue);
    cleanParameter(CleanString);
    for (std::string::iterator it = CleanString.begin(); it != CleanString.end(); it++) {

        if (*it == '\'') {
            Result << "'\\" << *it << "'";
        } else if (*it == '\\') {
            Result << "'\\\\'";
        } else if (*it == '\n') {
            Result << "'\\n'";
        } else if (*it != 0) {
            int nb = (int)*it & 0xff;
            Result << "'\\x" << std::hex << nb << "'";
        } else {
            continue;
        }

        uint32_t offset = 1;
        if (it + offset != CleanString.end()) {
            Result << ",";
        }
    }

    if (*Result.str().end() == ',')
        Result << "0};\n";
    else
        Result << ",0};\n";
    return std::regex_replace(Result.str(), std::regex(",,"), ",");
}




































// ///Working code below: 
// #include "Utils.h"
// #include <iostream>
// #include <regex>
// #include <random>
// #include <sstream>
// #include <variant>  // Include for std::variant and std::visit
// #include <cstring>  // Include for strlen
// #include <clang/AST/CommentLexer.h>
// // // Assuming LLVM headers are correctly included and linked if you're using llvm::outs

// using namespace Utils;

// // Using RNGVariant with std::variant for RNG types
// using RNGVariant = std::variant<std::mt19937, std::ranlux48_base, std::minstd_rand>;

// // Function to get a random generator

// RNGVariant getRandomGenerator() {
//     static std::random_device rd;
//     static std::mt19937 mt(rd());
//     static std::ranlux48_base rl48(rd());
//     static std::minstd_rand minstd(rd());
    
//     // Randomly select an RNG to use
//     std::uniform_int_distribution<int> dist(0, 2); // Adjust for the three options
//     int choice = dist(rd);
//     if (choice == 0) {
//         return mt;
//     } else if (choice == 1) {
//         return rl48;
//     } else {
//         return minstd;
//     }
// }

// std::string Utils::randomString(std::string::size_type Length) {
//     static auto &chrs = "0123456789"
//                         "abcdefghijklmnopqrstuvwxyz"
//                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

//     auto rng = getRandomGenerator();
//     std::uniform_int_distribution<std::string::size_type> pick(0, std::strlen(chrs) - 1);


//     std::string s;
//     s.reserve(Length);

//     // Add prefix to identify the random generator used
//     if (std::holds_alternative<std::mt19937>(rng)) {
//         s += "mt_";
//     } else if (std::holds_alternative<std::ranlux48_base>(rng)) {
//         s += "rl48_";
//     } else if (std::holds_alternative<std::minstd_rand>(rng)) {
//         s += "minstd_";
//     }

//     while (Length--) {
//         s += chrs[std::visit([&](auto& rng) -> std::string::size_type {
//             return pick(rng);
//         }, rng)];
//     }

//     return s;
// }
// std::string Utils::translateStringToIdentifier(const std::string &StrLiteral) {
//     std::string NewIdentifier = std::regex_replace(StrLiteral, std::regex("[^A-Za-z]"), "9");
//     return "mxt_" + NewIdentifier.substr(0, 6) + '_' + randomString(12);
// }


// void Utils::cleanParameter(std::string &Argument) {

//     auto Index = Argument.find_first_of('\"');

//     Argument.erase(Argument.begin(), Argument.begin() + Index + 1);

//     if (Argument.back() == '\"') {
//         Argument.pop_back();
//     }
// }


// std::string
// Utils::generateVariableDeclaration(const std::string &StringIdentifier, const std::string &StringValue, std::string StringType) {

//     std::stringstream Result;

//     //Result << "\n#ifdef _UNICODE\n\twchar_t\n";
//     //Result << "#else\n\tchar\n#endif\n\t";
//     if(!StringType.empty()){
//         auto pos = StringType.find('*');
//         if (pos != std::string::npos)
//             StringType.erase(pos);

//         Result << StringType << " " << StringIdentifier;
//         /*if (StringType.find("char") != std::string::npos && StringType.find("*") == std::string::npos) {
//         }*/
//         Result << "[]";

//         Result << " = {";
//     } else {
//         llvm::outs() << StringValue <<  " Oups\n";

//         Result << "TCHAR " << StringIdentifier << "[] = {";
//     }

//     auto CleanString = std::string(StringValue);
//     cleanParameter(CleanString);
//     for (std::string::iterator it = CleanString.begin(); it != CleanString.end(); it++) {

//         if (*it == '\'') {
//             Result << "'\\" << *it << "'";
//         } else if (*it == '\\') {
//             Result << "'\\\\'";
//         } else if (*it == '\n') {
//             Result << "'\\n'";
//         } else if (*it != 0) {
//             int nb = (int)*it & 0xff;
//             Result << "'\\x" << std::hex << nb << "'";
//         } else {
//             continue;
//         }

//         uint32_t offset = 1;
//         if (it + offset != CleanString.end()) {
//             Result << ",";
//         }
//     }

//     if (*Result.str().end() == ',')
//         Result << "0};\n";
//     else
//         Result << ",0};\n";
//     return std::regex_replace(Result.str(), std::regex(",,"), ",");
// }
























// using namespace Utils;

// // Adjusted RNGVariant to only include types that fit the expected interface
// using RNGVariant = std::variant<std::mt19937, std::ranlux48_base>;

// // Utility function to initialize and return a random generator variant
// RNGVariant getRandomGenerator() {
//     static std::random_device rd;
//     static std::mt19937 mt(rd());
//     static std::ranlux48_base rl48(rd());
//     static std::uniform_int_distribution<int> dist(0, 1); // Adjusted to select between two options

//     int choice = dist(rd);
//     if (choice == 0) {
//         return mt;
//     } else {
//         return rl48;
//     }
// }

// std::string Utils::randomString(std::string::size_type Length) {
//     static const char* chrs = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";

//     RNGVariant rng = getRandomGenerator();
//     std::uniform_int_distribution<std::string::size_type> pick(0, strlen(chrs) - 1);

//     std::string s;
//     s.reserve(Length);

//     while (Length--) {
//         s += chrs[std::visit([&](auto& rng) -> std::string::size_type {
//             return pick(rng);
//         }, rng)];
//     }

//     return s;
// }

// std::string Utils::translateStringToIdentifier(const std::string &StrLiteral) {
//     std::string NewIdentifier = std::regex_replace(StrLiteral, std::regex("[^A-Za-z]"), "9");
//     return "mxt_" + NewIdentifier.substr(0, 6) + '_' + randomString(12) + "enu";
// }

// void Utils::cleanParameter(std::string &Argument) {
//     auto Index = Argument.find_first_of('\"');
//     Argument.erase(Argument.begin(), Argument.begin() + Index + 1);

//     if (Argument.back() == '\"') {
//         Argument.pop_back();
//     }
// }

// std::string Utils::generateVariableDeclaration(const std::string &StringIdentifier, const std::string &StringValue, std::string StringType) {
//     std::stringstream Result;
//     if(!StringType.empty()){
//         auto pos = StringType.find('*');
//         if (pos != std::string::npos) StringType.erase(pos);

//         Result << StringType << " " << StringIdentifier << "[] = {";
//     } else {
//         llvm::outs() << StringValue <<  " Oups\n"; // This requires linking with LLVM libraries
//         Result << "TCHAR " << StringIdentifier << "[] = {";
//     }

//     auto CleanString = std::string(StringValue);
//     cleanParameter(CleanString);
//     for (auto it = CleanString.begin(); it != CleanString.end(); ++it) {
//         if (*it == '\'') {
//             Result << "'\\" << *it << "'";
//         } else if (*it == '\\') {
//             Result << "'\\\\'";
//         } else if (*it == '\n') {
//             Result << "'\\n'";
//         } else if (*it != 0) {
//             int nb = static_cast<int>(*it) & 0xff;
//             Result << "'\\x" << std::hex << nb << "'";
//         } else {
//             continue;
//         }

//         if (it + 1 != CleanString.end()) {
//             Result << ",";
//         }
//     }

//     Result << ",0};\n";
//     return std::regex_replace(Result.str(), std::regex(",,"), ",");
// }