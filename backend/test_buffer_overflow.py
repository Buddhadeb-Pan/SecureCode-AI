from buffer_overflow_analyzer import (
    analyze_c_cpp_buffer_overflow
)


test_code = r'''
#include <iostream>
#include <cstring>
#include <string>

using namespace std;

int main() {

    char username[10];
    gets(username);

    char password[8];
    scanf("%s", password);

    char safe_name[20];
    scanf("%19s", safe_name);

    char destination[10];
    memcpy(destination, "abcdefghijklmnop", 16);

    char name[12];
    cin >> name;

    std::string safe_input;
    cin >> safe_input;

    return 0;
}
'''


result = analyze_c_cpp_buffer_overflow(
    test_code
)


print("\nSTATUS:")
print(result.get("status"))

print("\nFINDINGS:")

for finding in result.get(
    "findings",
    []
):

    print("\n-----------------------------")

    print(
        "Type:",
        finding.get("type")
    )

    print(
        "Buffer:",
        finding.get("buffer")
    )

    print(
        "Buffer Size:",
        finding.get("buffer_size")
    )

    print(
        "Line:",
        finding.get("primary_line")
    )

    print(
        "Severity:",
        finding.get("severity")
    )

    print(
        "Confidence:",
        finding.get("confidence")
    )

    print(
        "Evidence Level:",
        finding.get("evidence_level")
    )

    print(
        "Description:",
        finding.get("description")
    )

    print(
        "Affected Lines:",
        finding.get("affected_lines")
    )

    print(
        "Analysis Method:",
        finding.get("analysis_method")
    )